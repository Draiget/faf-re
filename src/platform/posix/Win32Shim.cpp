// Engine addition (dedicated-server plan WPL.5): POSIX implementations of the Win32 and MSVC
// CRT calls declared in platform/posix/win32/Windows.h, for the Linux build. Windows builds do
// not compile this file.

#if !defined(_WIN32)

#include "platform/posix/win32/Windows.h"

#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>

#include <fcntl.h>
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

  [[nodiscard]] std::string SlashPath(const char* const path)
  {
    std::string out = path != nullptr ? path : "";
    for (char& c : out) {
      if (c == '\\') {
        c = '/';
      }
    }
    return out;
  }

  /// Every HANDLE this file hands out points at one of these.
  struct ShimHandle
  {
    enum class Kind { Event, Semaphore, Mutex, File };

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
    return object != nullptr && object->kind != ShimHandle::Kind::File ? static_cast<WaitObject*>(object) : nullptr;
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

DWORD SleepEx(const DWORD milliseconds, BOOL)
{
  Sleep(milliseconds);
  return 0;
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
  const std::string source = NarrowPath(from);
  const std::string target = NarrowPath(to);
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
  if (::mkdir(NarrowPath(path).c_str(), 0755) != 0) {
    SetErrnoError();
    return FALSE;
  }
  return TRUE;
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

#endif // !defined(_WIN32)
