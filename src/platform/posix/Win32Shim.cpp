// Engine addition (dedicated-server plan WPL.5): POSIX implementations of the Win32 and MSVC
// CRT calls declared in platform/posix/win32/Windows.h, for the Linux build. Windows builds do
// not compile this file.

#if !defined(_WIN32)

#include "platform/posix/win32/Windows.h"
#include "platform/posix/win32/io.h"
#include "gpg/core/containers/String.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <unordered_map>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <typeinfo>
#include <vector>

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <malloc.h>
#include <fnmatch.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

namespace
{
  thread_local DWORD tLastError = 0;

  [[nodiscard]] DWORD ErrnoToWin32(const int error) noexcept
  {
    switch (error) {
    case 0:
      return ERROR_SUCCESS;
    case ENOENT:
      return ERROR_FILE_NOT_FOUND;
    case ENOTDIR:
      return ERROR_PATH_NOT_FOUND;
    case EACCES:
    case EPERM:
      return ERROR_ACCESS_DENIED;
    case EEXIST:
      return ERROR_ALREADY_EXISTS;
    case EBADF:
      return ERROR_INVALID_HANDLE;
    case EINVAL:
      return ERROR_INVALID_PARAMETER;
    default:
      return static_cast<DWORD>(error);
    }
  }

  void SetErrnoError() noexcept
  {
    tLastError = ErrnoToWin32(errno);
  }

  /// UTF-8 of a wide (UTF-32 on Linux) path.
  [[nodiscard]] std::string NarrowPath(const wchar_t* const path)
  {
    std::string out;
    if (path == nullptr) {
      return out;
    }
    for (const wchar_t* p = path; *p != 0; ++p) {
      const std::uint32_t c = static_cast<std::uint32_t>(*p);
      if (c < 0x80u) {
        out.push_back(static_cast<char>(c == '\\' ? '/' : c));
      } else if (c < 0x800u) {
        out.push_back(static_cast<char>(0xC0u | (c >> 6)));
        out.push_back(static_cast<char>(0x80u | (c & 0x3Fu)));
      } else if (c < 0x10000u) {
        out.push_back(static_cast<char>(0xE0u | (c >> 12)));
        out.push_back(static_cast<char>(0x80u | ((c >> 6) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | (c & 0x3Fu)));
      } else {
        out.push_back(static_cast<char>(0xF0u | (c >> 18)));
        out.push_back(static_cast<char>(0x80u | ((c >> 12) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | ((c >> 6) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | (c & 0x3Fu)));
      }
    }
    return out;
  }

  /// The wide (UTF-32) form of a UTF-8 string.
  [[nodiscard]] std::wstring WidenUtf8(const std::string& text)
  {
    std::wstring out;
    for (std::size_t at = 0; at < text.size();) {
      const auto lead = static_cast<unsigned char>(text[at]);
      std::uint32_t c = lead;
      std::size_t extra = 0;
      if (lead >= 0xF0u) {
        c = lead & 0x07u;
        extra = 3;
      } else if (lead >= 0xE0u) {
        c = lead & 0x0Fu;
        extra = 2;
      } else if (lead >= 0xC0u) {
        c = lead & 0x1Fu;
        extra = 1;
      }
      ++at;
      for (std::size_t k = 0; k < extra && at < text.size(); ++k, ++at) {
        c = (c << 6) | (static_cast<unsigned char>(text[at]) & 0x3Fu);
      }
      out.push_back(static_cast<wchar_t>(c));
    }
    return out;
  }

  [[nodiscard]] bool SameNameIgnoringCase(const char* a, const char* b) noexcept
  {
    for (; *a != '\0' && *b != '\0'; ++a, ++b) {
      if (std::tolower(static_cast<unsigned char>(*a)) != std::tolower(static_cast<unsigned char>(*b))) {
        return false;
      }
    }
    return *a == *b;
  }

  /**
   * Plan WPL.15: a path as NTFS would find it, case-insensitively. When the path does not exist
   * as spelled, each component is looked up in its directory ignoring ASCII case and replaced
   * by the spelling on disk; the first component with no match and everything after it stay as
   * given (a file about to be created). The result names an existing file whenever Windows
   * would have found one.
   */
  [[nodiscard]] std::string ResolveCase(std::string path)
  {
    if (path.empty() || ::access(path.c_str(), F_OK) == 0) {
      return path;
    }
    std::string resolved = path[0] == '/' ? "/" : "";
    std::size_t at = path[0] == '/' ? 1 : 0;
    while (at <= path.size()) {
      const std::size_t slash = path.find('/', at);
      const std::size_t end = slash == std::string::npos ? path.size() : slash;
      const std::string component = path.substr(at, end - at);
      if (!component.empty()) {
        std::string candidate = resolved + component;
        if (::access(candidate.c_str(), F_OK) != 0 && component != "." && component != "..") {
          bool found = false;
          if (DIR* const dir = ::opendir(resolved.empty() ? "." : resolved.c_str())) {
            while (const dirent* const entry = ::readdir(dir)) {
              if (SameNameIgnoringCase(entry->d_name, component.c_str())) {
                candidate = resolved + entry->d_name;
                found = true;
                break;
              }
            }
            (void)::closedir(dir);
          }
          if (!found) {
            // Nothing to match here: keep the rest as it was spelled.
            return resolved + path.substr(at);
          }
        }
        resolved = candidate;
      }
      if (slash == std::string::npos) {
        break;
      }
      if (resolved.empty() || resolved.back() != '/') {
        resolved += '/';
      }
      at = slash + 1;
    }
    return resolved;
  }

  [[nodiscard]] std::string SlashPath(const char* const path)
  {
    std::string out = path != nullptr ? path : "";
    for (char& c : out) {
      if (c == '\\') {
        c = '/';
      }
    }
    return ResolveCase(std::move(out));
  }

  /// Every HANDLE this file hands out points at one of these.
  struct ShimHandle
  {
    enum class Kind { Event, Semaphore, Mutex, File, Mapping, Thread };

    explicit ShimHandle(const Kind kind) noexcept
      : kind(kind)
    {}
    virtual ~ShimHandle() = default;

    const Kind kind;
  };

  /// An event (manual or auto reset), a semaphore or a mutex: the objects the engine waits on.
  struct WaitObject final : ShimHandle
  {
    using ShimHandle::ShimHandle;

    bool manualReset = false;
    LONG count = 0; // event: 1 signalled; semaphore: the count; mutex: 1 when free
    LONG maximum = 1;
    std::thread::id owner{};
    LONG recursion = 0;
    std::mutex mutex;
    std::condition_variable signalled;

    [[nodiscard]] bool ReadyLocked() const noexcept
    {
      if (kind == Kind::Mutex) {
        return count > 0 || owner == std::this_thread::get_id();
      }
      return count > 0;
    }

    /// Takes the object (auto-reset events, semaphores and mutexes are consumed).
    void AcquireLocked() noexcept
    {
      switch (kind) {
      case Kind::Event:
        if (!manualReset) {
          count = 0;
        }
        break;
      case Kind::Semaphore:
        --count;
        break;
      case Kind::Mutex:
        if (owner == std::this_thread::get_id()) {
          ++recursion;
        } else {
          count = 0;
          owner = std::this_thread::get_id();
          recursion = 1;
        }
        break;
      default:
        break;
      }
    }
  };

  struct FileObject final : ShimHandle
  {
    FileObject() noexcept
      : ShimHandle(Kind::File)
    {}
    ~FileObject() override
    {
      if (fd >= 0) {
        (void)::close(fd);
      }
    }

    int fd = -1;
  };

  /// A file mapping: its own descriptor of the file and the file's size when it was made.
  struct MappingObject final : ShimHandle
  {
    MappingObject() noexcept
      : ShimHandle(Kind::Mapping)
    {}
    ~MappingObject() override
    {
      if (fd >= 0) {
        (void)::close(fd);
      }
    }

    int fd = -1;
    std::size_t size = 0;
  };

  /// One thread's queued asynchronous procedure calls.
  struct ApcQueue
  {
    std::mutex mutex;
    std::condition_variable queued;
    std::deque<std::pair<PAPCFUNC, ULONG_PTR>> calls;
  };

  /// Every thread's APC queue, by thread id; made by the thread itself or by OpenThread.
  std::mutex gApcQueuesLock;
  std::unordered_map<DWORD, std::shared_ptr<ApcQueue>> gApcQueues;

  [[nodiscard]] std::shared_ptr<ApcQueue> ApcQueueOf(const DWORD threadId)
  {
    const std::lock_guard<std::mutex> lock(gApcQueuesLock);
    std::shared_ptr<ApcQueue>& queue = gApcQueues[threadId];
    if (queue == nullptr) {
      queue = std::make_shared<ApcQueue>();
    }
    return queue;
  }

  /// The calling thread's queue, dropped from the registry when the thread exits.
  struct CurrentThreadApcQueue
  {
    DWORD threadId = 0;
    std::shared_ptr<ApcQueue> queue;

    ~CurrentThreadApcQueue()
    {
      if (queue != nullptr) {
        const std::lock_guard<std::mutex> lock(gApcQueuesLock);
        const auto found = gApcQueues.find(threadId);
        if (found != gApcQueues.end() && found->second == queue) {
          gApcQueues.erase(found);
        }
      }
    }
  };

  [[nodiscard]] ApcQueue& CurrentApcQueue()
  {
    thread_local CurrentThreadApcQueue current;
    if (current.queue == nullptr) {
      current.threadId = static_cast<DWORD>(::syscall(SYS_gettid));
      current.queue = ApcQueueOf(current.threadId);
    }
    return *current.queue;
  }

  /// Runs the calling thread's queued calls; true when there was at least one.
  bool RunQueuedApcs()
  {
    ApcQueue& queue = CurrentApcQueue();
    bool ran = false;
    for (;;) {
      std::pair<PAPCFUNC, ULONG_PTR> call{};
      {
        const std::lock_guard<std::mutex> lock(queue.mutex);
        if (queue.calls.empty()) {
          return ran;
        }
        call = queue.calls.front();
        queue.calls.pop_front();
      }
      call.first(call.second);
      ran = true;
    }
  }

  /// A thread opened by OpenThread: the queue its APCs go to.
  struct ThreadObject final : ShimHandle
  {
    ThreadObject() noexcept
      : ShimHandle(Kind::Thread)
    {}

    DWORD threadId = 0;
    std::shared_ptr<ApcQueue> queue;
  };

  /// The length of every view MapViewOfFile handed out, for UnmapViewOfFile.
  std::mutex gViewLock;
  std::vector<std::pair<const void*, std::size_t>> gViews;

  const HANDLE kCurrentThreadPseudoHandle = reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-2));
  const HANDLE kCurrentProcessPseudoHandle = reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-1));

  [[nodiscard]] ShimHandle* AsShimHandle(const HANDLE handle) noexcept
  {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE || handle == kCurrentThreadPseudoHandle) {
      return nullptr;
    }
    return static_cast<ShimHandle*>(handle);
  }

  [[nodiscard]] WaitObject* AsWaitObject(const HANDLE handle) noexcept
  {
    ShimHandle* const object = AsShimHandle(handle);
    return object != nullptr && (object->kind == ShimHandle::Kind::Event || object->kind == ShimHandle::Kind::Semaphore ||
                                 object->kind == ShimHandle::Kind::Mutex)
             ? static_cast<WaitObject*>(object)
             : nullptr;
  }

  [[nodiscard]] FileObject* AsFileObject(const HANDLE handle) noexcept
  {
    ShimHandle* const object = AsShimHandle(handle);
    return object != nullptr && object->kind == ShimHandle::Kind::File ? static_cast<FileObject*>(object) : nullptr;
  }

  [[nodiscard]] pthread_mutex_t* SectionMutex(CRITICAL_SECTION* const section) noexcept
  {
    static_assert(sizeof(pthread_mutex_t) <= sizeof(section->storage), "CRITICAL_SECTION storage too small");
    return reinterpret_cast<pthread_mutex_t*>(section->storage);
  }
} // namespace

// --- Synchronisation ---------------------------------------------------------------------

HANDLE CreateEventW(void*, const BOOL manualReset, const BOOL initialState, const wchar_t*)
{
  auto* const event = new WaitObject(ShimHandle::Kind::Event);
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
  auto* const semaphore = new WaitObject(ShimHandle::Kind::Semaphore);
  semaphore->count = initialCount;
  semaphore->maximum = maximumCount;
  return semaphore;
}

BOOL ReleaseSemaphore(const HANDLE handle, const LONG releaseCount, LONG* const previousCount)
{
  WaitObject* const object = AsWaitObject(handle);
  if (object == nullptr || object->kind != ShimHandle::Kind::Semaphore || releaseCount <= 0) {
    tLastError = ERROR_INVALID_HANDLE;
    return FALSE;
  }
  {
    std::lock_guard<std::mutex> lock(object->mutex);
    if (object->count + releaseCount > object->maximum) {
      tLastError = ERROR_INVALID_PARAMETER;
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

HANDLE CreateMutexW(void*, const BOOL initialOwner, const wchar_t*)
{
  auto* const mutex = new WaitObject(ShimHandle::Kind::Mutex);
  mutex->count = 1;
  if (initialOwner != FALSE) {
    mutex->AcquireLocked();
  }
  return mutex;
}

HANDLE CreateMutexA(void* const attributes, const BOOL initialOwner, const char*)
{
  return CreateMutexW(attributes, initialOwner, nullptr);
}

BOOL ReleaseMutex(const HANDLE handle)
{
  WaitObject* const object = AsWaitObject(handle);
  if (object == nullptr || object->kind != ShimHandle::Kind::Mutex) {
    tLastError = ERROR_INVALID_HANDLE;
    return FALSE;
  }
  {
    std::lock_guard<std::mutex> lock(object->mutex);
    if (object->owner != std::this_thread::get_id()) {
      tLastError = ERROR_ACCESS_DENIED;
      return FALSE;
    }
    if (--object->recursion == 0) {
      object->owner = std::thread::id{};
      object->count = 1;
    }
  }
  object->signalled.notify_one();
  return TRUE;
}

BOOL SetEvent(const HANDLE handle)
{
  WaitObject* const object = AsWaitObject(handle);
  if (object == nullptr || object->kind != ShimHandle::Kind::Event) {
    tLastError = ERROR_INVALID_HANDLE;
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
  if (object == nullptr || object->kind != ShimHandle::Kind::Event) {
    tLastError = ERROR_INVALID_HANDLE;
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
    tLastError = ERROR_INVALID_HANDLE;
    return WAIT_FAILED;
  }
  std::unique_lock<std::mutex> lock(object->mutex);
  if (milliseconds == INFINITE) {
    object->signalled.wait(lock, [object] { return object->ReadyLocked(); });
  } else if (!object->signalled.wait_for(
               lock, std::chrono::milliseconds(milliseconds), [object] { return object->ReadyLocked(); }
             )) {
    return WAIT_TIMEOUT;
  }
  object->AcquireLocked();
  return WAIT_OBJECT_0;
}

DWORD WaitForSingleObjectEx(const HANDLE handle, const DWORD milliseconds, const BOOL alertable)
{
  if (alertable == FALSE) {
    return WaitForSingleObject(handle, milliseconds);
  }
  WaitObject* const object = AsWaitObject(handle);
  if (object == nullptr) {
    tLastError = ERROR_INVALID_HANDLE;
    return WAIT_FAILED;
  }
  // Alertable: the object or a queued call, whichever comes first, in 1 ms slices.
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
  for (;;) {
    if (RunQueuedApcs()) {
      return WAIT_IO_COMPLETION;
    }
    {
      std::unique_lock<std::mutex> lock(object->mutex);
      if (object->signalled.wait_for(lock, std::chrono::milliseconds(1), [object] { return object->ReadyLocked(); })) {
        object->AcquireLocked();
        return WAIT_OBJECT_0;
      }
    }
    if (milliseconds != INFINITE && std::chrono::steady_clock::now() >= deadline) {
      return WAIT_TIMEOUT;
    }
  }
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
          tLastError = ERROR_INVALID_HANDLE;
          return WAIT_FAILED;
        }
        std::lock_guard<std::mutex> lock(object->mutex);
        all = object->ReadyLocked();
      }
      if (all) {
        for (DWORD index = 0; index < count; ++index) {
          WaitObject* const object = AsWaitObject(handles[index]);
          std::lock_guard<std::mutex> lock(object->mutex);
          object->AcquireLocked();
        }
        return WAIT_OBJECT_0;
      }
    } else {
      for (DWORD index = 0; index < count; ++index) {
        WaitObject* const object = AsWaitObject(handles[index]);
        if (object == nullptr) {
          tLastError = ERROR_INVALID_HANDLE;
          return WAIT_FAILED;
        }
        std::lock_guard<std::mutex> lock(object->mutex);
        if (object->ReadyLocked()) {
          object->AcquireLocked();
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
  ShimHandle* const object = AsShimHandle(handle);
  if (object == nullptr) {
    tLastError = ERROR_INVALID_HANDLE;
    return FALSE;
  }
  delete object;
  return TRUE;
}

void InitializeCriticalSection(CRITICAL_SECTION* const section)
{
  pthread_mutexattr_t attributes;
  (void)::pthread_mutexattr_init(&attributes);
  (void)::pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
  (void)::pthread_mutex_init(SectionMutex(section), &attributes);
  (void)::pthread_mutexattr_destroy(&attributes);
  section->initialized = true;
}

BOOL InitializeCriticalSectionAndSpinCount(CRITICAL_SECTION* const section, DWORD)
{
  InitializeCriticalSection(section);
  return TRUE;
}

void EnterCriticalSection(CRITICAL_SECTION* const section)
{
  (void)::pthread_mutex_lock(SectionMutex(section));
}

BOOL TryEnterCriticalSection(CRITICAL_SECTION* const section)
{
  return ::pthread_mutex_trylock(SectionMutex(section)) == 0 ? TRUE : FALSE;
}

void LeaveCriticalSection(CRITICAL_SECTION* const section)
{
  (void)::pthread_mutex_unlock(SectionMutex(section));
}

void DeleteCriticalSection(CRITICAL_SECTION* const section)
{
  if (section->initialized) {
    (void)::pthread_mutex_destroy(SectionMutex(section));
    section->initialized = false;
  }
}

// --- Threads, processes and time ---------------------------------------------------------

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

DWORD SleepEx(const DWORD milliseconds, const BOOL alertable)
{
  if (alertable == FALSE) {
    Sleep(milliseconds);
    return 0;
  }
  if (RunQueuedApcs()) {
    return WAIT_IO_COMPLETION;
  }
  ApcQueue& queue = CurrentApcQueue();
  {
    std::unique_lock<std::mutex> lock(queue.mutex);
    const auto hasCalls = [&queue] { return !queue.calls.empty(); };
    if (milliseconds == INFINITE) {
      queue.queued.wait(lock, hasCalls);
    } else if (!queue.queued.wait_for(lock, std::chrono::milliseconds(milliseconds), hasCalls)) {
      return 0;
    }
  }
  (void)RunQueuedApcs();
  return WAIT_IO_COMPLETION;
}

HANDLE OpenThread(DWORD, BOOL, const DWORD threadId)
{
  char taskPath[64]{};
  std::snprintf(taskPath, sizeof(taskPath), "/proc/self/task/%u", static_cast<unsigned>(threadId));
  if (::access(taskPath, F_OK) != 0) {
    tLastError = ERROR_INVALID_PARAMETER;
    return nullptr;
  }
  auto* const thread = new ThreadObject();
  thread->threadId = threadId;
  thread->queue = ApcQueueOf(threadId);
  return thread;
}

DWORD QueueUserAPC(const PAPCFUNC function, const HANDLE threadHandle, const ULONG_PTR data)
{
  ShimHandle* const object = AsShimHandle(threadHandle);
  std::shared_ptr<ApcQueue> queue;
  if (threadHandle == kCurrentThreadPseudoHandle) {
    queue = ApcQueueOf(static_cast<DWORD>(::syscall(SYS_gettid)));
  } else if (object != nullptr && object->kind == ShimHandle::Kind::Thread) {
    queue = static_cast<ThreadObject*>(object)->queue;
  }
  if (function == nullptr || queue == nullptr) {
    tLastError = ERROR_INVALID_HANDLE;
    return 0;
  }
  {
    const std::lock_guard<std::mutex> lock(queue->mutex);
    queue->calls.emplace_back(function, data);
  }
  queue->queued.notify_all();
  return 1;
}

HMODULE GetModuleHandleA(const char* const moduleName)
{
  void* const module = ::dlopen(moduleName, RTLD_NOW | RTLD_NOLOAD);
  if (module != nullptr) {
    (void)::dlclose(module); // GetModuleHandle takes no reference.
  }
  return module;
}

HMODULE GetModuleHandleW(const wchar_t* const moduleName)
{
  if (moduleName == nullptr) {
    extern char __executable_start;
    return &__executable_start;
  }
  return GetModuleHandleA(NarrowPath(moduleName).c_str());
}

BOOL InitOnceExecuteOnce(const PINIT_ONCE initOnce, const PINIT_ONCE_FN function, const PVOID parameter, PVOID* const context)
{
  for (;;) {
    int state = __atomic_load_n(&initOnce->state, __ATOMIC_ACQUIRE);
    if (state == 2) {
      return TRUE;
    }
    if (state == 0 && __atomic_compare_exchange_n(&initOnce->state, &state, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
      const BOOL done = function(initOnce, parameter, context);
      __atomic_store_n(&initOnce->state, done != FALSE ? 2 : 0, __ATOMIC_RELEASE);
      return done;
    }
    ::sched_yield();
  }
}

const wchar_t* GetCommandLineW()
{
  // Built once, without the heap (the allocator asks for it before it is set up).
  static wchar_t sCommandLine[8192];
  static INIT_ONCE sOnce = INIT_ONCE_STATIC_INIT;
  (void)InitOnceExecuteOnce(&sOnce, [](PINIT_ONCE, PVOID, PVOID*) -> BOOL {
    const int fd = ::open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      return TRUE;
    }
    char raw[8192];
    const ssize_t got = ::read(fd, raw, sizeof(raw) - 1);
    (void)::close(fd);
    std::size_t out = 0;
    for (ssize_t at = 0; at < got && out + 1 < sizeof(sCommandLine) / sizeof(sCommandLine[0]); ++at) {
      // Arguments are NUL-separated; the trailing NUL ends the line.
      if (raw[at] == '\0') {
        if (at + 1 < got) {
          sCommandLine[out++] = L' ';
        }
      } else {
        sCommandLine[out++] = static_cast<wchar_t>(static_cast<unsigned char>(raw[at]));
      }
    }
    sCommandLine[out] = L'\0';
    return TRUE;
  }, nullptr, nullptr);
  return sCommandLine;
}

HANDLE GetProcessHeap()
{
  static int sProcessHeap = 0;
  return &sProcessHeap;
}

HANDLE HeapCreate(DWORD, SIZE_T, SIZE_T)
{
  return GetProcessHeap();
}

void* HeapAlloc(HANDLE, const DWORD flags, const SIZE_T bytes)
{
  void* const block = (flags & HEAP_ZERO_MEMORY) != 0 ? std::calloc(1, bytes != 0 ? bytes : 1) : std::malloc(bytes != 0 ? bytes : 1);
  if (block == nullptr) {
    tLastError = ERROR_NOT_ENOUGH_MEMORY;
  }
  return block;
}

BOOL HeapFree(HANDLE, DWORD, void* const memory)
{
  std::free(memory);
  return TRUE;
}

SIZE_T HeapSize(HANDLE, DWORD, const void* const memory)
{
  return memory != nullptr ? ::malloc_usable_size(const_cast<void*>(memory)) : static_cast<SIZE_T>(-1);
}

HMODULE LoadLibraryA(const char* const fileName)
{
  void* const module = ::dlopen(fileName, RTLD_NOW | RTLD_LOCAL);
  if (module == nullptr) {
    tLastError = ERROR_FILE_NOT_FOUND;
  }
  return module;
}

void* GetProcAddress(const HMODULE module, const char* const procName)
{
  return module != nullptr ? ::dlsym(module, procName) : nullptr;
}

BOOL FreeLibrary(const HMODULE module)
{
  return module != nullptr && ::dlclose(module) == 0 ? TRUE : FALSE;
}

DWORD GetTickCount()
{
  timespec now{};
  ::clock_gettime(CLOCK_MONOTONIC, &now);
  return static_cast<DWORD>(
    static_cast<std::uint64_t>(now.tv_sec) * 1000u + static_cast<std::uint64_t>(now.tv_nsec) / 1000000u
  );
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

BOOL GetVersionExW(OSVERSIONINFOW* const info)
{
  if (info == nullptr) {
    return FALSE;
  }
  info->dwMajorVersion = 10;
  info->dwMinorVersion = 0;
  info->dwBuildNumber = 0;
  info->dwPlatformId = VER_PLATFORM_WIN32_NT;
  info->szCSDVersion[0] = 0;
  return TRUE;
}

DWORD GetLastError()
{
  return tLastError;
}

void SetLastError(const DWORD error)
{
  tLastError = error;
}

BOOL GetProcessAffinityMask(HANDLE, DWORD_PTR* const processMask, DWORD_PTR* const systemMask)
{
  cpu_set_t set;
  CPU_ZERO(&set);
  if (::sched_getaffinity(0, sizeof(set), &set) != 0) {
    SetErrnoError();
    return FALSE;
  }
  DWORD_PTR mask = 0;
  for (unsigned cpu = 0; cpu < sizeof(DWORD_PTR) * 8; ++cpu) {
    if (CPU_ISSET(cpu, &set)) {
      mask |= DWORD_PTR{1} << cpu;
    }
  }
  if (processMask != nullptr) {
    *processMask = mask;
  }
  if (systemMask != nullptr) {
    *systemMask = mask;
  }
  return TRUE;
}

DWORD GetEnvironmentVariableA(const char* const name, char* const buffer, const DWORD size)
{
  const char* const value = name != nullptr ? std::getenv(name) : nullptr;
  if (value == nullptr) {
    tLastError = ERROR_ENVVAR_NOT_FOUND;
    return 0;
  }
  const std::size_t length = std::strlen(value);
  if (buffer == nullptr || size <= length) {
    return static_cast<DWORD>(length + 1); // the size needed, terminator included
  }
  std::memcpy(buffer, value, length + 1);
  return static_cast<DWORD>(length);
}

void OutputDebugStringA(const char* const text)
{
  if (text != nullptr) {
    (void)std::fputs(text, stderr);
  }
}

void OutputDebugStringW(const wchar_t* const text)
{
  if (text != nullptr) {
    (void)std::fputs(NarrowPath(text).c_str(), stderr);
  }
}

BOOL SetThreadPriority(HANDLE, int)
{
  // A scheduling hint; the server keeps the default policy.
  return TRUE;
}

DWORD_PTR SetThreadAffinityMask(const HANDLE thread, const DWORD_PTR mask)
{
  if (thread != kCurrentThreadPseudoHandle || mask == 0) {
    tLastError = ERROR_INVALID_PARAMETER;
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
    tLastError = ERROR_INVALID_PARAMETER;
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

BOOL GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*, DWORD* const length)
{
  if (length != nullptr) {
    *length = 0;
  }
  tLastError = ERROR_NOT_SUPPORTED;
  return FALSE;
}

// --- Memory ------------------------------------------------------------------------------

LPVOID VirtualAlloc(const LPVOID address, const SIZE_T size, const DWORD allocationType, const DWORD protect)
{
  const int protection = protect == PAGE_NOACCESS ? PROT_NONE : protect == PAGE_READONLY ? PROT_READ : (PROT_READ | PROT_WRITE);
  if (address != nullptr && (allocationType & MEM_COMMIT) != 0 && (allocationType & MEM_RESERVE) == 0) {
    // Commit within a reservation.
    return ::mprotect(address, size, protection) == 0 ? address : nullptr;
  }
  void* const mapped =
    ::mmap(address, size, (allocationType & MEM_COMMIT) != 0 ? protection : PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapped == MAP_FAILED) {
    SetErrnoError();
    return nullptr;
  }
  return mapped;
}

BOOL VirtualFree(const LPVOID address, const SIZE_T size, const DWORD freeType)
{
  if ((freeType & MEM_RELEASE) != 0) {
    // MEM_RELEASE passes size 0 on Windows; the reservation's size is not known here.
    return size != 0 && ::munmap(address, size) == 0 ? TRUE : FALSE;
  }
  return ::mprotect(address, size, PROT_NONE) == 0 ? TRUE : FALSE;
}

SIZE_T VirtualQuery(const LPCVOID address, MEMORY_BASIC_INFORMATION* const info, const SIZE_T length)
{
  if (info == nullptr || length < sizeof(MEMORY_BASIC_INFORMATION)) {
    return 0;
  }
  const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(address);
  std::ifstream maps("/proc/self/maps");
  std::string line;
  while (std::getline(maps, line)) {
    unsigned long begin = 0;
    unsigned long end = 0;
    char permissions[5] = {};
    if (std::sscanf(line.c_str(), "%lx-%lx %4s", &begin, &end, permissions) != 3) {
      continue;
    }
    if (target < begin || target >= end) {
      continue;
    }
    *info = MEMORY_BASIC_INFORMATION{};
    info->BaseAddress = reinterpret_cast<LPVOID>(begin);
    info->AllocationBase = reinterpret_cast<LPVOID>(begin);
    info->RegionSize = end - begin;
    const bool readable = permissions[0] == 'r';
    const bool writable = permissions[1] == 'w';
    info->State = readable ? MEM_COMMIT : MEM_RESERVE;
    info->Protect = !readable ? PAGE_NOACCESS : writable ? PAGE_READWRITE : PAGE_READONLY;
    info->AllocationProtect = info->Protect;
    info->Type = permissions[3] == 'p' ? MEM_PRIVATE : 0u;
    return sizeof(MEMORY_BASIC_INFORMATION);
  }
  *info = MEMORY_BASIC_INFORMATION{};
  info->BaseAddress = const_cast<LPVOID>(address);
  info->State = MEM_FREE;
  info->Protect = PAGE_NOACCESS;
  return sizeof(MEMORY_BASIC_INFORMATION);
}

HLOCAL LocalFree(const HLOCAL memory)
{
  std::free(memory);
  return nullptr;
}

// --- Files -------------------------------------------------------------------------------

HANDLE CreateFileA(
  const char* const path, const DWORD desiredAccess, DWORD, void*, const DWORD creation, DWORD, HANDLE
)
{
  int flags = 0;
  const bool reading = (desiredAccess & GENERIC_READ) != 0;
  const bool writing = (desiredAccess & GENERIC_WRITE) != 0;
  flags |= reading && writing ? O_RDWR : writing ? O_WRONLY : O_RDONLY;
  switch (creation) {
  case CREATE_NEW:
    flags |= O_CREAT | O_EXCL;
    break;
  case CREATE_ALWAYS:
    flags |= O_CREAT | O_TRUNC;
    break;
  case OPEN_ALWAYS:
    flags |= O_CREAT;
    break;
  case TRUNCATE_EXISTING:
    flags |= O_TRUNC;
    break;
  default:
    break;
  }
  const std::string unixPath = SlashPath(path);
  const int fd = ::open(unixPath.c_str(), flags | O_CLOEXEC, 0644);
  if (fd < 0) {
    SetErrnoError();
    return INVALID_HANDLE_VALUE;
  }
  auto* const file = new FileObject();
  file->fd = fd;
  tLastError = ERROR_SUCCESS;
  return file;
}

HANDLE CreateFileW(
  const wchar_t* const path,
  const DWORD desiredAccess,
  const DWORD shareMode,
  void* const security,
  const DWORD creation,
  const DWORD flags,
  const HANDLE templateFile
)
{
  return CreateFileA(NarrowPath(path).c_str(), desiredAccess, shareMode, security, creation, flags, templateFile);
}

BOOL ReadFile(const HANDLE handle, void* const buffer, const DWORD bytesToRead, DWORD* const bytesRead, void*)
{
  FileObject* const file = AsFileObject(handle);
  if (file == nullptr) {
    tLastError = ERROR_INVALID_HANDLE;
    return FALSE;
  }
  std::size_t total = 0;
  while (total < bytesToRead) {
    const ssize_t got = ::read(file->fd, static_cast<char*>(buffer) + total, bytesToRead - total);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      SetErrnoError();
      if (bytesRead != nullptr) {
        *bytesRead = static_cast<DWORD>(total);
      }
      return FALSE;
    }
    if (got == 0) {
      break;
    }
    total += static_cast<std::size_t>(got);
  }
  if (bytesRead != nullptr) {
    *bytesRead = static_cast<DWORD>(total);
  }
  return TRUE;
}

BOOL WriteFile(const HANDLE handle, const void* const buffer, const DWORD bytesToWrite, DWORD* const bytesWritten, void*)
{
  FileObject* const file = AsFileObject(handle);
  if (file == nullptr) {
    tLastError = ERROR_INVALID_HANDLE;
    return FALSE;
  }
  std::size_t total = 0;
  while (total < bytesToWrite) {
    const ssize_t put = ::write(file->fd, static_cast<const char*>(buffer) + total, bytesToWrite - total);
    if (put < 0) {
      if (errno == EINTR) {
        continue;
      }
      SetErrnoError();
      if (bytesWritten != nullptr) {
        *bytesWritten = static_cast<DWORD>(total);
      }
      return FALSE;
    }
    total += static_cast<std::size_t>(put);
  }
  if (bytesWritten != nullptr) {
    *bytesWritten = static_cast<DWORD>(total);
  }
  return TRUE;
}

BOOL SetFilePointerEx(const HANDLE handle, const LARGE_INTEGER distance, LARGE_INTEGER* const newPosition, const DWORD moveMethod)
{
  FileObject* const file = AsFileObject(handle);
  if (file == nullptr) {
    tLastError = ERROR_INVALID_HANDLE;
    return FALSE;
  }
  const int whence = moveMethod == FILE_CURRENT ? SEEK_CUR : moveMethod == FILE_END ? SEEK_END : SEEK_SET;
  const off_t position = ::lseek(file->fd, static_cast<off_t>(distance.QuadPart), whence);
  if (position < 0) {
    SetErrnoError();
    return FALSE;
  }
  if (newPosition != nullptr) {
    newPosition->QuadPart = static_cast<std::int64_t>(position);
  }
  return TRUE;
}

DWORD SetFilePointer(const HANDLE handle, const LONG distance, LONG* const distanceHigh, const DWORD moveMethod)
{
  LARGE_INTEGER move{};
  move.QuadPart = distanceHigh != nullptr
                    ? (static_cast<std::int64_t>(*distanceHigh) << 32) | static_cast<std::uint32_t>(distance)
                    : static_cast<std::int64_t>(distance);
  LARGE_INTEGER result{};
  if (!SetFilePointerEx(handle, move, &result, moveMethod)) {
    return INVALID_SET_FILE_POINTER;
  }
  if (distanceHigh != nullptr) {
    *distanceHigh = static_cast<LONG>(result.QuadPart >> 32);
  }
  return static_cast<DWORD>(result.QuadPart & 0xFFFFFFFF);
}

BOOL GetFileSizeEx(const HANDLE handle, LARGE_INTEGER* const size)
{
  FileObject* const file = AsFileObject(handle);
  struct stat status{};
  if (file == nullptr || ::fstat(file->fd, &status) != 0) {
    tLastError = ERROR_INVALID_HANDLE;
    return FALSE;
  }
  size->QuadPart = static_cast<std::int64_t>(status.st_size);
  return TRUE;
}

DWORD GetFileSize(const HANDLE handle, DWORD* const sizeHigh)
{
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(handle, &size)) {
    return INVALID_FILE_SIZE;
  }
  if (sizeHigh != nullptr) {
    *sizeHigh = static_cast<DWORD>(size.QuadPart >> 32);
  }
  return static_cast<DWORD>(size.QuadPart & 0xFFFFFFFF);
}

HANDLE CreateFileMappingW(
  const HANDLE file, void*, const DWORD protect, const DWORD maximumSizeHigh, const DWORD maximumSizeLow, const wchar_t*
)
{
  FileObject* const source = AsFileObject(file);
  struct stat status{};
  if (source == nullptr || protect != PAGE_READONLY || maximumSizeHigh != 0 || maximumSizeLow != 0 ||
      ::fstat(source->fd, &status) != 0) {
    tLastError = ERROR_INVALID_PARAMETER;
    return nullptr;
  }
  if (status.st_size == 0) {
    // Windows refuses to map an empty file.
    tLastError = ERROR_FILE_INVALID;
    return nullptr;
  }
  const int fd = ::fcntl(source->fd, F_DUPFD_CLOEXEC, 0);
  if (fd < 0) {
    SetErrnoError();
    return nullptr;
  }
  auto* const mapping = new MappingObject();
  mapping->fd = fd;
  mapping->size = static_cast<std::size_t>(status.st_size);
  tLastError = ERROR_SUCCESS;
  return mapping;
}

void* MapViewOfFile(
  const HANDLE mappingHandle, const DWORD desiredAccess, const DWORD offsetHigh, const DWORD offsetLow, const std::size_t bytes
)
{
  ShimHandle* const object = AsShimHandle(mappingHandle);
  if (object == nullptr || object->kind != ShimHandle::Kind::Mapping || desiredAccess != FILE_MAP_READ ||
      offsetHigh != 0 || offsetLow != 0) {
    tLastError = ERROR_INVALID_PARAMETER;
    return nullptr;
  }
  const auto* const mapping = static_cast<const MappingObject*>(object);
  const std::size_t length = bytes != 0 ? bytes : mapping->size;
  void* const view = ::mmap(nullptr, length, PROT_READ, MAP_PRIVATE, mapping->fd, 0);
  if (view == MAP_FAILED) {
    SetErrnoError();
    return nullptr;
  }
  const std::lock_guard<std::mutex> lock(gViewLock);
  gViews.emplace_back(view, length);
  return view;
}

BOOL UnmapViewOfFile(const void* const view)
{
  std::size_t length = 0;
  {
    const std::lock_guard<std::mutex> lock(gViewLock);
    const auto found = std::find_if(gViews.begin(), gViews.end(), [view](const auto& entry) { return entry.first == view; });
    if (found == gViews.end()) {
      tLastError = ERROR_INVALID_PARAMETER;
      return FALSE;
    }
    length = found->second;
    gViews.erase(found);
  }
  return ::munmap(const_cast<void*>(view), length) == 0 ? TRUE : FALSE;
}

BOOL FlushFileBuffers(const HANDLE handle)
{
  FileObject* const file = AsFileObject(handle);
  return file != nullptr && ::fsync(file->fd) == 0 ? TRUE : FALSE;
}

BOOL SetEndOfFile(const HANDLE handle)
{
  FileObject* const file = AsFileObject(handle);
  if (file == nullptr) {
    return FALSE;
  }
  const off_t position = ::lseek(file->fd, 0, SEEK_CUR);
  return position >= 0 && ::ftruncate(file->fd, position) == 0 ? TRUE : FALSE;
}

DWORD GetFileAttributesA(const char* const path)
{
  struct stat status{};
  if (::stat(SlashPath(path).c_str(), &status) != 0) {
    SetErrnoError();
    return INVALID_FILE_ATTRIBUTES;
  }
  DWORD attributes = S_ISDIR(status.st_mode) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
  if ((status.st_mode & S_IWUSR) == 0) {
    attributes |= FILE_ATTRIBUTE_READONLY;
  }
  return attributes;
}

DWORD GetFileAttributesW(const wchar_t* const path)
{
  return GetFileAttributesA(NarrowPath(path).c_str());
}

BOOL MoveFileExW(const wchar_t* const from, const wchar_t* const to, const DWORD flags)
{
  const std::string source = ResolveCase(NarrowPath(from));
  const std::string target = ResolveCase(NarrowPath(to));
  if ((flags & MOVEFILE_REPLACE_EXISTING) == 0 && ::access(target.c_str(), F_OK) == 0) {
    tLastError = ERROR_ALREADY_EXISTS;
    return FALSE;
  }
  if (::rename(source.c_str(), target.c_str()) != 0) {
    SetErrnoError();
    return FALSE;
  }
  return TRUE;
}

BOOL MoveFileW(const wchar_t* const from, const wchar_t* const to)
{
  return MoveFileExW(from, to, 0);
}

BOOL DeleteFileA(const char* const path)
{
  if (::unlink(SlashPath(path).c_str()) != 0) {
    SetErrnoError();
    return FALSE;
  }
  return TRUE;
}

BOOL DeleteFileW(const wchar_t* const path)
{
  return DeleteFileA(NarrowPath(path).c_str());
}

BOOL CreateDirectoryW(const wchar_t* const path, void*)
{
  if (::mkdir(ResolveCase(NarrowPath(path)).c_str(), 0755) != 0) {
    SetErrnoError();
    return FALSE;
  }
  return TRUE;
}

BOOL ReplaceFileW(
  const wchar_t* const replacedFile, const wchar_t* const replacementFile, const wchar_t* const backupFile, DWORD, void*, void*
)
{
  const std::string replaced = ResolveCase(NarrowPath(replacedFile));
  const std::string replacement = ResolveCase(NarrowPath(replacementFile));
  if (::access(replaced.c_str(), F_OK) != 0) {
    tLastError = ERROR_FILE_NOT_FOUND;
    return FALSE;
  }
  if (backupFile != nullptr) {
    const std::string backup = ResolveCase(NarrowPath(backupFile));
    if (::link(replaced.c_str(), backup.c_str()) != 0 && errno != EEXIST) {
      SetErrnoError();
      return FALSE;
    }
  }
  if (::rename(replacement.c_str(), replaced.c_str()) != 0) {
    SetErrnoError();
    return FALSE;
  }
  return TRUE;
}

BOOL CreateDirectoryA(const char* const path, void*)
{
  if (::mkdir(SlashPath(path).c_str(), 0755) != 0) {
    SetErrnoError();
    return FALSE;
  }
  return TRUE;
}

char* _fullpath(char* const absolutePath, const char* const relativePath, const std::size_t maxLength)
{
  if (relativePath == nullptr) {
    errno = EINVAL;
    return nullptr;
  }
  std::error_code error;
  const std::string full = std::filesystem::absolute(SlashPath(relativePath), error).lexically_normal().string();
  if (error) {
    errno = ENOENT;
    return nullptr;
  }
  if (absolutePath == nullptr) {
    return ::strdup(full.c_str());
  }
  if (full.size() + 1 > maxLength) {
    errno = ERANGE;
    return nullptr;
  }
  std::memcpy(absolutePath, full.c_str(), full.size() + 1);
  return absolutePath;
}

int WideCharToMultiByte(
  UINT, DWORD, const wchar_t* const wide, const int wideLength, char* const multiByte, const int multiByteLength,
  const char*, BOOL* const usedDefaultChar
)
{
  if (usedDefaultChar != nullptr) {
    *usedDefaultChar = FALSE;
  }
  if (wide == nullptr) {
    tLastError = ERROR_INVALID_PARAMETER;
    return 0;
  }
  // UTF-8, with the terminator converted too when the length is -1.
  const std::size_t count = wideLength < 0 ? std::wcslen(wide) : static_cast<std::size_t>(wideLength);
  std::string out = NarrowPath(std::wstring(wide, count).c_str());
  if (wideLength < 0) {
    out.push_back('\0');
  }
  if (multiByteLength == 0) {
    return static_cast<int>(out.size());
  }
  if (multiByte == nullptr || out.size() > static_cast<std::size_t>(multiByteLength)) {
    tLastError = ERROR_INSUFFICIENT_BUFFER;
    return 0;
  }
  std::memcpy(multiByte, out.data(), out.size());
  return static_cast<int>(out.size());
}

int MultiByteToWideChar(
  UINT, DWORD, const char* const multiByte, const int multiByteLength, wchar_t* const wide, const int wideLength
)
{
  if (multiByte == nullptr) {
    tLastError = ERROR_INVALID_PARAMETER;
    return 0;
  }
  const std::size_t count = multiByteLength < 0 ? std::strlen(multiByte) : static_cast<std::size_t>(multiByteLength);
  std::wstring out = WidenUtf8(std::string(multiByte, count));
  if (multiByteLength < 0) {
    out.push_back(L'\0');
  }
  if (wideLength == 0) {
    return static_cast<int>(out.size());
  }
  if (wide == nullptr || out.size() > static_cast<std::size_t>(wideLength)) {
    tLastError = ERROR_INSUFFICIENT_BUFFER;
    return 0;
  }
  std::wmemcpy(wide, out.data(), out.size());
  return static_cast<int>(out.size());
}

BOOL PathFileExistsW(const wchar_t* const path)
{
  return ::access(ResolveCase(NarrowPath(path)).c_str(), F_OK) == 0 ? TRUE : FALSE;
}

DWORD GetModuleFileNameW(const HMODULE module, wchar_t* const fileName, const DWORD size)
{
  if (module != nullptr || fileName == nullptr || size == 0) {
    tLastError = ERROR_INVALID_PARAMETER;
    return 0;
  }
  char exe[4096]{};
  const ssize_t length = ::readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  if (length <= 0) {
    SetErrnoError();
    return 0;
  }
  const std::wstring wide = WidenUtf8(std::string(exe, static_cast<std::size_t>(length)));
  if (wide.size() >= size) {
    // Windows truncates and reports the buffer as too small.
    std::wmemcpy(fileName, wide.c_str(), size - 1);
    fileName[size - 1] = L'\0';
    tLastError = ERROR_INSUFFICIENT_BUFFER;
    return size;
  }
  std::wmemcpy(fileName, wide.c_str(), wide.size() + 1);
  tLastError = ERROR_SUCCESS;
  return static_cast<DWORD>(wide.size());
}

BOOL SetProcessAffinityMask(const HANDLE process, const DWORD_PTR processMask)
{
  if (process != kCurrentProcessPseudoHandle || processMask == 0) {
    tLastError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  cpu_set_t wanted;
  CPU_ZERO(&wanted);
  for (unsigned cpu = 0; cpu < sizeof(DWORD_PTR) * 8; ++cpu) {
    if ((processMask & (DWORD_PTR{1} << cpu)) != 0) {
      CPU_SET(cpu, &wanted);
    }
  }
  if (::sched_setaffinity(0, sizeof(wanted), &wanted) != 0) {
    SetErrnoError();
    return FALSE;
  }
  return TRUE;
}

HRESULT SHGetFolderPathW(HWND, const int folder, HANDLE, DWORD, wchar_t* const path)
{
  if (path == nullptr) {
    return E_INVALIDARG;
  }
  const char* const home = std::getenv("HOME");
  if (home == nullptr || home[0] == '\0') {
    return E_FAIL;
  }
  const auto fromEnvironment = [home](const char* const variable, const char* const fallback) {
    const char* const value = std::getenv(variable);
    return value != nullptr && value[0] == '/' ? std::string(value) : std::string(home) + fallback;
  };
  std::string resolved;
  switch (folder & ~CSIDL_FLAG_CREATE) {
  case CSIDL_LOCAL_APPDATA:
    resolved = fromEnvironment("XDG_DATA_HOME", "/.local/share");
    break;
  case CSIDL_APPDATA:
    resolved = fromEnvironment("XDG_CONFIG_HOME", "/.config");
    break;
  case CSIDL_PERSONAL:
    resolved = std::string(home) + "/Documents";
    break;
  case CSIDL_DESKTOP:
  case CSIDL_DESKTOPDIRECTORY:
    resolved = std::string(home) + "/Desktop";
    break;
  default:
    return E_FAIL;
  }
  const std::wstring wide = WidenUtf8(resolved);
  if (wide.size() >= MAX_PATH) {
    return E_FAIL;
  }
  std::wmemcpy(path, wide.c_str(), wide.size() + 1);
  return S_OK;
}

int SHFileOperationA(SHFILEOPSTRUCTA*)
{
  return static_cast<int>(ERROR_NOT_SUPPORTED);
}

int SHFileOperationW(SHFILEOPSTRUCTW*)
{
  return static_cast<int>(ERROR_NOT_SUPPORTED);
}

BOOL DosDateTimeToFileTime(const WORD fatDate, const WORD fatTime, FILETIME* const fileTime)
{
  std::tm parts{};
  parts.tm_year = ((fatDate >> 9) & 0x7F) + 80;
  parts.tm_mon = ((fatDate >> 5) & 0x0F) - 1;
  parts.tm_mday = fatDate & 0x1F;
  parts.tm_hour = (fatTime >> 11) & 0x1F;
  parts.tm_min = (fatTime >> 5) & 0x3F;
  parts.tm_sec = (fatTime & 0x1F) * 2;
  // FAT times are local times; Windows keeps them as they are in the FILETIME (no zone
  // conversion), so they are read here as UTC.
  const std::time_t seconds = ::timegm(&parts);
  if (seconds == static_cast<std::time_t>(-1)) {
    return FALSE;
  }
  // FILETIME: 100 ns intervals since 1601-01-01.
  const std::uint64_t ticks = (static_cast<std::uint64_t>(seconds) + 11644473600ull) * 10000000ull;
  fileTime->dwLowDateTime = static_cast<DWORD>(ticks & 0xFFFFFFFFu);
  fileTime->dwHighDateTime = static_cast<DWORD>(ticks >> 32);
  return TRUE;
}

// --- Messages ----------------------------------------------------------------------------

DWORD FormatMessageA(const DWORD flags, const void*, const DWORD messageId, DWORD, char* const buffer, const DWORD size, va_list*)
{
  const char* const text = std::strerror(static_cast<int>(messageId));
  const std::size_t length = std::strlen(text);
  if ((flags & FORMAT_MESSAGE_ALLOCATE_BUFFER) != 0) {
    auto* const allocated = static_cast<char*>(std::malloc(length + 1));
    if (allocated == nullptr) {
      return 0;
    }
    std::memcpy(allocated, text, length + 1);
    *reinterpret_cast<char**>(buffer) = allocated;
    return static_cast<DWORD>(length);
  }
  if (buffer == nullptr || size == 0) {
    return 0;
  }
  const std::size_t copied = length < size - 1 ? length : size - 1;
  std::memcpy(buffer, text, copied);
  buffer[copied] = 0;
  return static_cast<DWORD>(copied);
}

DWORD FormatMessageW(const DWORD flags, const void*, const DWORD messageId, DWORD, wchar_t* const buffer, const DWORD size, va_list*)
{
  const char* const text = std::strerror(static_cast<int>(messageId));
  const std::size_t length = std::strlen(text);
  if ((flags & FORMAT_MESSAGE_ALLOCATE_BUFFER) != 0) {
    auto* const allocated = static_cast<wchar_t*>(std::malloc((length + 1) * sizeof(wchar_t)));
    if (allocated == nullptr) {
      return 0;
    }
    for (std::size_t i = 0; i <= length; ++i) {
      allocated[i] = static_cast<unsigned char>(text[i]);
    }
    *reinterpret_cast<wchar_t**>(buffer) = allocated;
    return static_cast<DWORD>(length);
  }
  if (buffer == nullptr || size == 0) {
    return 0;
  }
  const std::size_t copied = length < size - 1 ? length : size - 1;
  for (std::size_t i = 0; i < copied; ++i) {
    buffer[i] = static_cast<unsigned char>(text[i]);
  }
  buffer[copied] = 0;
  return static_cast<DWORD>(copied);
}

// --- MSVC CRT names ----------------------------------------------------------------------

char* _ctime64(const __time64_t* const time) noexcept
{
  const std::time_t value = static_cast<std::time_t>(*time);
  return std::ctime(&value);
}

void _ftime64(__timeb64* const out) noexcept
{
  timeval now{};
  ::gettimeofday(&now, nullptr);
  out->time = static_cast<__time64_t>(now.tv_sec);
  out->millitm = static_cast<unsigned short>(now.tv_usec / 1000);
  out->timezone = 0;
  out->dstflag = 0;
}

int fopen_s(std::FILE** const file, const char* const path, const char* const mode) noexcept
{
  if (file == nullptr) {
    return EINVAL;
  }
  *file = std::fopen(SlashPath(path).c_str(), mode);
  return *file != nullptr ? 0 : errno;
}

int _wfopen_s(std::FILE** const file, const wchar_t* const path, const wchar_t* const mode) noexcept
{
  return fopen_s(file, NarrowPath(path).c_str(), NarrowPath(mode).c_str());
}

int strncpy_s(char* const dest, const std::size_t destSize, const char* const src, const std::size_t count) noexcept
{
  if (dest == nullptr || destSize == 0) {
    return EINVAL;
  }
  if (src == nullptr) {
    dest[0] = 0;
    return EINVAL;
  }
  std::size_t length = 0;
  while (length < count && src[length] != 0) {
    ++length;
  }
  if (count == _TRUNCATE && length >= destSize) {
    length = destSize - 1;
  } else if (length >= destSize) {
    dest[0] = 0;
    return ERANGE;
  }
  std::memcpy(dest, src, length);
  dest[length] = 0;
  return 0;
}

int strcpy_s(char* const dest, const std::size_t destSize, const char* const src) noexcept
{
  return strncpy_s(dest, destSize, src, src != nullptr ? std::strlen(src) : 0);
}

int vsprintf_s(char* const buffer, const std::size_t size, const char* const format, va_list arguments) noexcept
{
  if (buffer == nullptr || size == 0 || format == nullptr) {
    return -1;
  }
  const int written = std::vsnprintf(buffer, size, format, arguments);
  if (written < 0 || static_cast<std::size_t>(written) >= size) {
    buffer[0] = 0;
    return -1;
  }
  return written;
}

int sprintf_s(char* const buffer, const std::size_t size, const char* const format, ...) noexcept
{
  va_list arguments;
  va_start(arguments, format);
  const int written = vsprintf_s(buffer, size, format, arguments);
  va_end(arguments);
  return written;
}

int _memicmp(const void* const lhs, const void* const rhs, const std::size_t count) noexcept
{
  const auto* const a = static_cast<const unsigned char*>(lhs);
  const auto* const b = static_cast<const unsigned char*>(rhs);
  for (std::size_t i = 0; i < count; ++i) {
    const int ca = std::tolower(a[i]);
    const int cb = std::tolower(b[i]);
    if (ca != cb) {
      return ca - cb;
    }
  }
  return 0;
}

unsigned int _controlfp(const unsigned int newValue, const unsigned int mask) noexcept
{
  // Windows x64: the rounding and exception-mask fields apply to the x87 control word and to
  // MXCSR; the precision field is not supported (ignored). Only the rounding field and the
  // exception masks are mapped; the engine passes _MCW_PC only, which is ignored as on x64.
  std::uint16_t x87 = 0;
  __asm__ volatile("fnstcw %0" : "=m"(x87));
  std::uint32_t mxcsr = 0;
  __asm__ volatile("stmxcsr %0" : "=m"(mxcsr));
  if ((mask & _MCW_RC) != 0) {
    const unsigned int rc = (newValue & _MCW_RC) >> 8; // CRT 0..3 = near, down, up, chop
    x87 = static_cast<std::uint16_t>((x87 & ~0x0C00u) | (rc << 10));
    mxcsr = (mxcsr & ~0x6000u) | (rc << 13);
    __asm__ volatile("fldcw %0" ::"m"(x87));
    __asm__ volatile("ldmxcsr %0" ::"m"(mxcsr));
  }
  const unsigned int rcBits = ((mxcsr >> 13) & 3u) << 8;
  return rcBits;
}

// --- More of the same --------------------------------------------------------------------

namespace
{
  constexpr std::uint64_t kFileTimeUnixEpoch = 116444736000000000ull; // 1970-01-01 in FILETIME ticks

  void ToFileTime(const std::uint64_t ticks, FILETIME* const out) noexcept
  {
    out->dwLowDateTime = static_cast<DWORD>(ticks & 0xFFFFFFFFu);
    out->dwHighDateTime = static_cast<DWORD>(ticks >> 32);
  }

  [[nodiscard]] std::uint64_t FromFileTime(const FILETIME& in) noexcept
  {
    return (static_cast<std::uint64_t>(in.dwHighDateTime) << 32) | in.dwLowDateTime;
  }

  void ToSystemTime(const std::tm& parts, const unsigned milliseconds, SYSTEMTIME* const out) noexcept
  {
    out->wYear = static_cast<WORD>(parts.tm_year + 1900);
    out->wMonth = static_cast<WORD>(parts.tm_mon + 1);
    out->wDayOfWeek = static_cast<WORD>(parts.tm_wday);
    out->wDay = static_cast<WORD>(parts.tm_mday);
    out->wHour = static_cast<WORD>(parts.tm_hour);
    out->wMinute = static_cast<WORD>(parts.tm_min);
    out->wSecond = static_cast<WORD>(parts.tm_sec);
    out->wMilliseconds = static_cast<WORD>(milliseconds);
  }
} // namespace

void GetSystemTimeAsFileTime(FILETIME* const fileTime)
{
  timespec now{};
  ::clock_gettime(CLOCK_REALTIME, &now);
  ToFileTime(
    kFileTimeUnixEpoch + static_cast<std::uint64_t>(now.tv_sec) * 10000000ull + static_cast<std::uint64_t>(now.tv_nsec) / 100u,
    fileTime
  );
}

BOOL FileTimeToLocalFileTime(const FILETIME* const fileTime, FILETIME* const localFileTime)
{
  const std::uint64_t ticks = FromFileTime(*fileTime);
  const std::time_t seconds = static_cast<std::time_t>((ticks - kFileTimeUnixEpoch) / 10000000ull);
  std::tm local{};
  ::localtime_r(&seconds, &local);
  ToFileTime(ticks + static_cast<std::uint64_t>(static_cast<std::int64_t>(local.tm_gmtoff) * 10000000ll), localFileTime);
  return TRUE;
}

BOOL FileTimeToSystemTime(const FILETIME* const fileTime, SYSTEMTIME* const systemTime)
{
  const std::uint64_t ticks = FromFileTime(*fileTime);
  const std::time_t seconds = static_cast<std::time_t>((ticks - kFileTimeUnixEpoch) / 10000000ull);
  std::tm parts{};
  ::gmtime_r(&seconds, &parts);
  ToSystemTime(parts, static_cast<unsigned>((ticks / 10000u) % 1000u), systemTime);
  return TRUE;
}

void GetLocalTime(SYSTEMTIME* const systemTime)
{
  timespec now{};
  ::clock_gettime(CLOCK_REALTIME, &now);
  std::tm parts{};
  ::localtime_r(&now.tv_sec, &parts);
  ToSystemTime(parts, static_cast<unsigned>(now.tv_nsec / 1000000), systemTime);
}

void GetSystemTime(SYSTEMTIME* const systemTime)
{
  timespec now{};
  ::clock_gettime(CLOCK_REALTIME, &now);
  std::tm parts{};
  ::gmtime_r(&now.tv_sec, &parts);
  ToSystemTime(parts, static_cast<unsigned>(now.tv_nsec / 1000000), systemTime);
}

BOOL GetFileAttributesExA(const char* const path, const GET_FILEEX_INFO_LEVELS level, void* const information)
{
  if (level != GetFileExInfoStandard || information == nullptr) {
    tLastError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  struct stat status{};
  if (::stat(SlashPath(path).c_str(), &status) != 0) {
    SetErrnoError();
    return FALSE;
  }
  auto* const data = static_cast<WIN32_FILE_ATTRIBUTE_DATA*>(information);
  *data = WIN32_FILE_ATTRIBUTE_DATA{};
  data->dwFileAttributes = S_ISDIR(status.st_mode) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
  if ((status.st_mode & S_IWUSR) == 0) {
    data->dwFileAttributes |= FILE_ATTRIBUTE_READONLY;
  }
  const auto toTicks = [](const timespec& time) {
    return kFileTimeUnixEpoch + static_cast<std::uint64_t>(time.tv_sec) * 10000000ull + static_cast<std::uint64_t>(time.tv_nsec) / 100u;
  };
  ToFileTime(toTicks(status.st_ctim), &data->ftCreationTime);
  ToFileTime(toTicks(status.st_atim), &data->ftLastAccessTime);
  ToFileTime(toTicks(status.st_mtim), &data->ftLastWriteTime);
  const std::uint64_t size = static_cast<std::uint64_t>(status.st_size);
  data->nFileSizeHigh = static_cast<DWORD>(size >> 32);
  data->nFileSizeLow = static_cast<DWORD>(size & 0xFFFFFFFFu);
  return TRUE;
}

BOOL GetFileAttributesExW(const wchar_t* const path, const GET_FILEEX_INFO_LEVELS level, void* const information)
{
  return GetFileAttributesExA(NarrowPath(path).c_str(), level, information);
}

void GetCurrentProcessorNumberEx(PROCESSOR_NUMBER* const number)
{
  const int cpu = ::sched_getcpu();
  number->Group = 0;
  number->Number = static_cast<BYTE>(cpu >= 0 ? cpu : 0);
  number->Reserved = 0;
}

BOOL SetThreadGroupAffinity(const HANDLE thread, const GROUP_AFFINITY* const affinity, GROUP_AFFINITY* const previous)
{
  if (affinity == nullptr || affinity->Group != 0) {
    tLastError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  const DWORD_PTR previousMask = SetThreadAffinityMask(thread, affinity->Mask);
  if (previousMask == 0) {
    return FALSE;
  }
  if (previous != nullptr) {
    *previous = GROUP_AFFINITY{};
    previous->Mask = previousMask;
  }
  return TRUE;
}

BOOL SetThreadIdealProcessorEx(const HANDLE thread, PROCESSOR_NUMBER* const ideal, PROCESSOR_NUMBER* const previous)
{
  if (thread != kCurrentThreadPseudoHandle || ideal == nullptr || ideal->Group != 0) {
    tLastError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  if (previous != nullptr) {
    GetCurrentProcessorNumberEx(previous);
  }
  return TRUE;
}

BOOL GetNumaProcessorNode(UCHAR, UCHAR* const nodeNumber)
{
  if (nodeNumber != nullptr) {
    *nodeNumber = 0;
  }
  return TRUE;
}

BOOL GetNumaNodeProcessorMask(const UCHAR node, ULONGLONG* const processorMask)
{
  if (node != 0 || processorMask == nullptr) {
    return FALSE;
  }
  DWORD_PTR process = 0;
  DWORD_PTR system = 0;
  (void)GetProcessAffinityMask(GetCurrentProcess(), &process, &system);
  *processorMask = system;
  return TRUE;
}

int _vsnprintf(char* const buffer, const std::size_t count, const char* const format, va_list arguments) noexcept
{
  // MSVC: the text, terminated when it is shorter than `count`; exactly `count` characters
  // and no terminator when it fills the buffer; -1 (and `count` characters) when it does not fit.
  va_list copy;
  va_copy(copy, arguments);
  const int needed = std::vsnprintf(nullptr, 0, format, copy);
  va_end(copy);
  if (needed < 0) {
    return -1;
  }
  std::string full(static_cast<std::size_t>(needed) + 1, '\0');
  (void)std::vsnprintf(full.data(), full.size(), format, arguments);
  const std::size_t length = static_cast<std::size_t>(needed);
  if (length < count) {
    std::memcpy(buffer, full.data(), length + 1);
    return needed;
  }
  if (count > 0) {
    std::memcpy(buffer, full.data(), count);
  }
  return length == count ? needed : -1;
}
int _vsnwprintf(wchar_t* const buffer, const std::size_t count, const wchar_t* const format, va_list arguments) noexcept
{
  const int written = std::vswprintf(buffer, count, format, arguments);
  return written < 0 ? -1 : written;
}

int _snprintf(char* const buffer, const std::size_t count, const char* const format, ...) noexcept
{
  va_list arguments;
  va_start(arguments, format);
  const int written = _vsnprintf(buffer, count, format, arguments);
  va_end(arguments);
  return written;
}

namespace
{
  /// One `_findfirst64` search: the matches, sorted, and the next one to hand out.
  struct FindSearch
  {
    std::vector<__finddata64_t> matches;
    std::size_t next = 0;
  };

  [[nodiscard]] __time64_t ToTime64(const struct timespec& time) noexcept
  {
    return static_cast<__time64_t>(time.tv_sec);
  }
} // namespace

std::intptr_t _findfirst64(const char* const spec, __finddata64_t* const data)
{
  if (spec == nullptr || data == nullptr) {
    errno = EINVAL;
    return -1;
  }
  const std::string path = SlashPath(spec);
  const std::size_t slash = path.find_last_of('/');
  const std::string directory = slash == std::string::npos ? std::string(".") : slash == 0 ? std::string("/") : path.substr(0, slash);
  std::string pattern = slash == std::string::npos ? path : path.substr(slash + 1);
  if (pattern == "*.*") {
    pattern = "*";
  }

  DIR* const dir = ::opendir(directory.c_str());
  if (dir == nullptr) {
    errno = ENOENT;
    return -1;
  }
  auto search = std::make_unique<FindSearch>();
  while (const dirent* const entry = ::readdir(dir)) {
    if (::fnmatch(pattern.c_str(), entry->d_name, FNM_CASEFOLD) != 0) {
      continue;
    }
    __finddata64_t match{};
    const std::size_t length = std::min(std::strlen(entry->d_name), sizeof(match.name) - 1);
    std::memcpy(match.name, entry->d_name, length);
    match.name[length] = '\0';
    struct stat status{};
    const std::string full = directory + "/" + entry->d_name;
    if (::stat(full.c_str(), &status) == 0) {
      match.attrib = S_ISDIR(status.st_mode) ? _A_SUBDIR : _A_ARCH;
      if ((status.st_mode & S_IWUSR) == 0) {
        match.attrib |= _A_RDONLY;
      }
      match.time_create = ToTime64(status.st_ctim);
      match.time_access = ToTime64(status.st_atim);
      match.time_write = ToTime64(status.st_mtim);
      match.size = S_ISDIR(status.st_mode) ? 0 : static_cast<std::int64_t>(status.st_size);
    }
    search->matches.push_back(match);
  }
  (void)::closedir(dir);
  if (search->matches.empty()) {
    errno = ENOENT;
    return -1;
  }

  // NTFS keeps a directory's names in upper-cased order, which is the order FindNextFile
  // and so the CRT report them in (plan WPL.15: the engine's one comparison for it).
  std::sort(search->matches.begin(), search->matches.end(), [](const __finddata64_t& a, const __finddata64_t& b) {
    return gpg::STR_FileNameOrderLess(a.name, b.name);
  });

  *data = search->matches[0];
  search->next = 1;
  return reinterpret_cast<std::intptr_t>(search.release());
}

int _findnext64(const std::intptr_t handle, __finddata64_t* const data)
{
  auto* const search = reinterpret_cast<FindSearch*>(handle);
  if (handle == -1 || search == nullptr || data == nullptr) {
    errno = EINVAL;
    return -1;
  }
  if (search->next >= search->matches.size()) {
    errno = ENOENT;
    return -1;
  }
  *data = search->matches[search->next++];
  return 0;
}

int _findclose(const std::intptr_t handle)
{
  if (handle == -1 || handle == 0) {
    errno = EINVAL;
    return -1;
  }
  delete reinterpret_cast<FindSearch*>(handle);
  return 0;
}

// The MSVC CRT's copies of the command line (moho::CFG_GetArgs and the startup helpers read
// them). glibc passes argc and argv to the initialisers in .init_array, so they are set before
// any of the engine's static initialisers or main run.
int __argc = 0;
char** __argv = nullptr;

namespace
{
  __attribute__((constructor(101))) void CaptureCommandLine(const int argc, char** const argv, char**)
  {
    __argc = argc;
    __argv = argv;
  }
} // namespace

// MSVC's polymorphic typeid entry point (gpg/core/reflection/Reflection.cpp calls it on objects
// of unknown dynamic type). In the Itanium ABI every vtable of an object, primary or secondary,
// holds the complete object's type_info in the slot before its address point.
extern "C" void* __RTtypeid(void* const object)
{
  if (object == nullptr) {
    throw std::bad_typeid();
  }
  void* const* const vtable = *static_cast<void* const* const*>(object);
  return vtable[-1];
}

#endif // !defined(_WIN32)
