// Engine addition (dedicated-server plan WPL.5): POSIX implementations of the Win32 and MSVC
// CRT calls declared in platform/posix/win32/Windows.h, for the Linux build. Windows builds do
// not compile this file.

#if !FAFRE_PLATFORM_WINDOWS

#include "platform/posix/win32/Windows.h"
#include "platform/posix/win32/io.h"
#include "gpg/core/containers/String.h"
#include "platform/posix/NativePath.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <typeinfo>
#include <vector>

#include "platform/FpControl.h"
#include "platform/posix/SystemPosix.h"

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

namespace
{
  // A file's times as Windows names them. macOS records when a file was created (its birth time);
  // Linux's stat has no such field, and the inode change time stands in for it.
#if FAFRE_PLATFORM_MACOS // struct stat's st_*timespec fields and st_birthtimespec
  [[nodiscard]] const timespec& StatCreationTime(
    const struct stat& status
  ) noexcept
  {
    return status.st_birthtimespec;
  }
  [[nodiscard]] const timespec& StatAccessTime(
    const struct stat& status
  ) noexcept
  {
    return status.st_atimespec;
  }
  [[nodiscard]] const timespec& StatWriteTime(
    const struct stat& status
  ) noexcept
  {
    return status.st_mtimespec;
  }
#else
  [[nodiscard]] const timespec& StatCreationTime(
    const struct stat& status
  ) noexcept
  {
    return status.st_ctim;
  }
  [[nodiscard]] const timespec& StatAccessTime(
    const struct stat& status
  ) noexcept
  {
    return status.st_atim;
  }
  [[nodiscard]] const timespec& StatWriteTime(
    const struct stat& status
  ) noexcept
  {
    return status.st_mtim;
  }
#endif
} // namespace

namespace
{
  thread_local DWORD tLastError = 0;

  [[nodiscard]] DWORD ErrnoToWin32(
    const int error
  ) noexcept
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
  [[nodiscard]] std::string NarrowPath(
    const wchar_t* const path
  )
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
  [[nodiscard]] std::wstring WidenUtf8(
    const std::string& text
  )
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

  /// Where NextCodePoint puts a byte that isn't UTF-8: past Unicode, so it folds to nothing and
  /// matches only itself (a Latin-1 name on disk is no UTF-8 letter).
  constexpr std::uint32_t kNotUtf8Byte = 0x110000u;

  /**
   * The code point well-formed UTF-8 has at `at`, which moves past it. A byte that doesn't start
   * one (a stray continuation byte, an overlong form, a surrogate, a code point past U+10FFFF) is
   * kNotUtf8Byte plus the byte, and `at` moves one byte: such a name matches only its own bytes.
   */
  [[nodiscard]] std::uint32_t NextCodePoint(
    const char*& at
  ) noexcept
  {
    const auto byte = [&at](const std::size_t k) {
      return static_cast<unsigned char>(at[k]);
    };
    const unsigned char lead = byte(0);
    if (lead < 0x80u) {
      ++at;
      return lead;
    }
    std::size_t extra = 0;
    unsigned char low = 0x80u;  // the second byte's range, which rules out overlong forms,
    unsigned char high = 0xBFu; // surrogates and code points past U+10FFFF
    std::uint32_t c = 0;
    if (lead >= 0xC2u && lead <= 0xDFu) {
      extra = 1;
      c = lead & 0x1Fu;
    } else if (lead >= 0xE0u && lead <= 0xEFu) {
      extra = 2;
      c = lead & 0x0Fu;
      low = lead == 0xE0u ? 0xA0u : 0x80u;
      high = lead == 0xEDu ? 0x9Fu : 0xBFu;
    } else if (lead >= 0xF0u && lead <= 0xF4u) {
      extra = 3;
      c = lead & 0x07u;
      low = lead == 0xF0u ? 0x90u : 0x80u;
      high = lead == 0xF4u ? 0x8Fu : 0xBFu;
    }
    bool wellFormed = extra != 0 && byte(1) >= low && byte(1) <= high;
    for (std::size_t k = 2; wellFormed && k <= extra; ++k) {
      wellFormed = (byte(k) & 0xC0u) == 0x80u;
    }
    if (!wellFormed) {
      ++at;
      return kNotUtf8Byte + lead;
    }
    for (std::size_t k = 1; k <= extra; ++k) {
      c = (c << 6) | (byte(k) & 0x3Fu);
    }
    at += extra + 1;
    return c;
  }

  struct NtfsCasePair
  {
    std::uint16_t letter;
    std::uint16_t upper;
  };

  /// Windows' upper-case table, the one NTFS compares names by ($UpCase): every BMP letter from
  /// U+0080 whose upper case differs (tools/linux/ntfs_upcase_table.py).
  constexpr NtfsCasePair kNtfsUpcase[] = {
#include "platform/posix/NtfsUpcaseTable.inc"
  };

  [[maybe_unused]] [[nodiscard]] constexpr bool SortedByLetter() noexcept
  {
    for (std::size_t k = 1; k < std::size(kNtfsUpcase); ++k) {
      if (kNtfsUpcase[k - 1].letter >= kNtfsUpcase[k].letter) {
        return false;
      }
    }
    return true;
  }
  static_assert(SortedByLetter(), "NtfsUpcaseTable.inc must be sorted by letter (binary search)");

  /**
   * A letter as NTFS compares names, by its upper case: Windows' own table, which is narrower than
   * Unicode's ('ı', 'ſ', 'µ', 'ς', 'ǅ', Georgian and Cherokee letters keep their own case there), and
   * ASCII folded here, without the process's locale (Lua's os.setlocale can change that). Letters
   * past U+FFFF, which NTFS compares as UTF-16 halves, don't fold.
   */
  [[nodiscard]] std::uint32_t NtfsUpcase(
    const std::uint32_t c
  ) noexcept
  {
    if (c < 0x80u) {
      return c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c;
    }
    if (c > 0xFFFFu) {
      return c;
    }
    const auto* const end = std::end(kNtfsUpcase);
    const auto* const found =
      std::lower_bound(std::begin(kNtfsUpcase), end, c, [](const NtfsCasePair& pair, const std::uint32_t letter) {
      return pair.letter < letter;
    });
    return found != end && found->letter == c ? found->upper : c;
  }

  /**
   * Whether two names are one on NTFS (NtfsUpcase letter by letter): 'Игрок' and 'игрок', 'Ä' and 'ä'
   * are one name there.
   */
  [[nodiscard]] bool SameNameIgnoringCase(
    const char* a,
    const char* b
  ) noexcept
  {
    while (*a != '\0' && *b != '\0') {
      const std::uint32_t ca = NextCodePoint(a);
      const std::uint32_t cb = NextCodePoint(b);
      if (ca != cb && NtfsUpcase(ca) != NtfsUpcase(cb)) {
        return false;
      }
    }
    return *a == *b;
  }

  /**
   * Windows' match of one name against a FindFirstFile wildcard: '*' any run of letters, '?' one,
   * letters compared as NTFS compares names, and "*.*" every name, with or without a dot. ('[' is
   * no wildcard there.)
   */
  [[nodiscard]] bool ShellNameMatches(
    const char* const pattern,
    const char* const name
  ) noexcept
  {
    if (std::strcmp(pattern, "*.*") == 0) {
      return true;
    }
    const char* p = pattern;
    const char* n = name;
    const char* starPattern = nullptr;
    const char* starName = nullptr;
    while (*n != '\0') {
      if (*p == '*') {
        starPattern = ++p;
        starName = n;
        continue;
      }
      if (*p != '\0') {
        const char* nextP = p;
        const char* nextN = n;
        const std::uint32_t cp = NextCodePoint(nextP);
        const std::uint32_t cn = NextCodePoint(nextN);
        if (cp == '?' || cp == cn || NtfsUpcase(cp) == NtfsUpcase(cn)) {
          p = nextP;
          n = nextN;
          continue;
        }
      }
      if (starPattern == nullptr) {
        return false;
      }
      // Let the last '*' take one more letter of the name.
      p = starPattern;
      (void)NextCodePoint(starName);
      n = starName;
    }
    while (*p == '*') {
      ++p;
    }
    return *p == '\0';
  }

  // Plan WPR.23: the `--path-spelling` file, and the pairs it already holds.
  std::atomic<std::FILE*> sPathSpellingTrace{nullptr};
  std::mutex sPathSpellingLock;
  std::unordered_set<std::string> sPathSpellingSeen;

  /**
   * Plan WPL.15: a path as NTFS would find it, case-insensitively. When the path does not exist
   * as spelled, each component is looked up in its directory ignoring ASCII case and replaced
   * by the spelling on disk; the first component with no match and everything after it stay as
   * given (a file about to be created). The result names an existing file whenever Windows
   * would have found one.
   */
  [[nodiscard]] std::string ResolveCaseOnDisk(
    std::string path
  )
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

  [[nodiscard]] std::string ResolveCase(
    std::string path
  )
  {
    if (sPathSpellingTrace.load(std::memory_order_relaxed) == nullptr) {
      return ResolveCaseOnDisk(std::move(path));
    }
    std::string resolved = ResolveCaseOnDisk(path);
    // The lookup can also drop doubled slashes, which are no spelling.
    const auto singleSlashes = [](std::string text) {
      text.erase(
        std::unique(
          text.begin(),
          text.end(),
          [](const char a, const char b) {
        return a == '/' && b == '/';
      }
        ),
        text.end()
      );
      return text;
    };
    if (singleSlashes(resolved) != singleSlashes(path)) {
      std::lock_guard<std::mutex> guard(sPathSpellingLock);
      std::string line = path + "\t" + resolved + "\n";
      if (
        std::FILE* const file = sPathSpellingTrace.load(std::memory_order_relaxed);
        file != nullptr && sPathSpellingSeen.insert(line).second
      ) {
        (void)std::fputs(line.c_str(), file);
        (void)std::fflush(file);
      }
    }
    return resolved;
  }

  [[nodiscard]] std::string SlashPath(
    const char* const path
  )
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
    enum class Kind
    {
      Event,
      Semaphore,
      Mutex,
      File,
      Mapping,
      Thread
    };

    explicit ShimHandle(
      const Kind kind
    ) noexcept
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

  [[nodiscard]] std::shared_ptr<ApcQueue> ApcQueueOf(
    const DWORD threadId
  )
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
      current.threadId = static_cast<DWORD>(platform::posix::CurrentThreadId());
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

  /// The open handles, as Windows keeps them: a HANDLE is its object's address, this table holds one
  /// reference and every call that uses a handle holds another while it runs. A closed handle then
  /// fails with ERROR_INVALID_HANDLE instead of reaching freed memory (a connector thread may still
  /// signal an event its owner has closed, as ~CSimDriver does before its client manager stops), and an
  /// object another thread is waiting on or signalling lives until that call returns.
  /// Built on first use and never destroyed: static constructors in other files create events before
  /// this file's globals would exist, and threads may still signal while the process exits.
  struct HandleTable
  {
    std::shared_mutex lock;
    std::unordered_map<HANDLE, std::shared_ptr<ShimHandle>> handles;
  };

  [[nodiscard]] HandleTable& Handles()
  {
    static HandleTable* const table = new HandleTable();
    return *table;
  }

  [[nodiscard]] HANDLE Register(
    std::shared_ptr<ShimHandle> object
  )
  {
    const HANDLE handle = object.get();
    HandleTable& table = Handles();
    const std::unique_lock lock(table.lock);
    table.handles.emplace(handle, std::move(object));
    return handle;
  }

  [[nodiscard]] std::shared_ptr<ShimHandle> AsShimHandle(
    const HANDLE handle
  )
  {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE || handle == kCurrentThreadPseudoHandle) {
      return nullptr;
    }
    HandleTable& table = Handles();
    const std::shared_lock lock(table.lock);
    const auto found = table.handles.find(handle);
    return found != table.handles.end() ? found->second : nullptr;
  }

  [[nodiscard]] std::shared_ptr<WaitObject> AsWaitObject(
    const HANDLE handle
  )
  {
    std::shared_ptr<ShimHandle> object = AsShimHandle(handle);
    return object != nullptr &&
        (object->kind == ShimHandle::Kind::Event || object->kind == ShimHandle::Kind::Semaphore ||
         object->kind == ShimHandle::Kind::Mutex)
      ? std::static_pointer_cast<WaitObject>(std::move(object))
      : nullptr;
  }

  [[nodiscard]] std::shared_ptr<FileObject> AsFileObject(
    const HANDLE handle
  )
  {
    std::shared_ptr<ShimHandle> object = AsShimHandle(handle);
    return object != nullptr && object->kind == ShimHandle::Kind::File
      ? std::static_pointer_cast<FileObject>(std::move(object))
      : nullptr;
  }

  [[nodiscard]] pthread_mutex_t* SectionMutex(
    CRITICAL_SECTION* const section
  ) noexcept
  {
    static_assert(sizeof(pthread_mutex_t) <= sizeof(section->storage), "CRITICAL_SECTION storage too small");
    return reinterpret_cast<pthread_mutex_t*>(section->storage);
  }
} // namespace

std::string platform::posix::NativePath(
  const char* const path
)
{
  return SlashPath(path);
}

// --- Synchronisation ---------------------------------------------------------------------

HANDLE CreateEventW(
  void*,
  const BOOL manualReset,
  const BOOL initialState,
  const wchar_t*
)
{
  const auto event = std::make_shared<WaitObject>(ShimHandle::Kind::Event);
  event->manualReset = manualReset != FALSE;
  event->count = initialState != FALSE ? 1 : 0;
  return Register(event);
}

HANDLE CreateEventA(
  void* const attributes,
  const BOOL manualReset,
  const BOOL initialState,
  const char*
)
{
  return CreateEventW(attributes, manualReset, initialState, nullptr);
}

HANDLE CreateSemaphoreW(
  void*,
  const LONG initialCount,
  const LONG maximumCount,
  const wchar_t*
)
{
  const auto semaphore = std::make_shared<WaitObject>(ShimHandle::Kind::Semaphore);
  semaphore->count = initialCount;
  semaphore->maximum = maximumCount;
  return Register(semaphore);
}

BOOL ReleaseSemaphore(
  const HANDLE handle,
  const LONG releaseCount,
  LONG* const previousCount
)
{
  const std::shared_ptr<WaitObject> object = AsWaitObject(handle);
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

HANDLE CreateMutexW(
  void*,
  const BOOL initialOwner,
  const wchar_t*
)
{
  const auto mutex = std::make_shared<WaitObject>(ShimHandle::Kind::Mutex);
  mutex->count = 1;
  if (initialOwner != FALSE) {
    mutex->AcquireLocked();
  }
  return Register(mutex);
}

HANDLE CreateMutexA(
  void* const attributes,
  const BOOL initialOwner,
  const char*
)
{
  return CreateMutexW(attributes, initialOwner, nullptr);
}

BOOL ReleaseMutex(
  const HANDLE handle
)
{
  const std::shared_ptr<WaitObject> object = AsWaitObject(handle);
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

BOOL SetEvent(
  const HANDLE handle
)
{
  const std::shared_ptr<WaitObject> object = AsWaitObject(handle);
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

BOOL ResetEvent(
  const HANDLE handle
)
{
  const std::shared_ptr<WaitObject> object = AsWaitObject(handle);
  if (object == nullptr || object->kind != ShimHandle::Kind::Event) {
    tLastError = ERROR_INVALID_HANDLE;
    return FALSE;
  }
  std::lock_guard<std::mutex> lock(object->mutex);
  object->count = 0;
  return TRUE;
}

DWORD WaitForSingleObject(
  const HANDLE handle,
  const DWORD milliseconds
)
{
  const std::shared_ptr<WaitObject> object = AsWaitObject(handle);
  if (object == nullptr) {
    tLastError = ERROR_INVALID_HANDLE;
    return WAIT_FAILED;
  }
  std::unique_lock<std::mutex> lock(object->mutex);
  if (milliseconds == INFINITE) {
    object->signalled.wait(lock, [object] {
      return object->ReadyLocked();
    });
  } else if (!object->signalled.wait_for(lock, std::chrono::milliseconds(milliseconds), [object] {
    return object->ReadyLocked();
  })) {
    return WAIT_TIMEOUT;
  }
  object->AcquireLocked();
  return WAIT_OBJECT_0;
}

DWORD WaitForSingleObjectEx(
  const HANDLE handle,
  const DWORD milliseconds,
  const BOOL alertable
)
{
  if (alertable == FALSE) {
    return WaitForSingleObject(handle, milliseconds);
  }
  const std::shared_ptr<WaitObject> object = AsWaitObject(handle);
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
      if (object->signalled.wait_for(lock, std::chrono::milliseconds(1), [object] {
        return object->ReadyLocked();
      })) {
        object->AcquireLocked();
        return WAIT_OBJECT_0;
      }
    }
    if (milliseconds != INFINITE && std::chrono::steady_clock::now() >= deadline) {
      return WAIT_TIMEOUT;
    }
  }
}

DWORD WaitForMultipleObjects(
  const DWORD count,
  const HANDLE* const handles,
  const BOOL waitAll,
  const DWORD milliseconds
)
{
  // Polls: the engine waits on a handful of handles at most. The objects are looked up once, and held
  // for the whole wait as Windows holds them.
  std::vector<std::shared_ptr<WaitObject>> objects(count);
  for (DWORD index = 0; index < count; ++index) {
    objects[index] = AsWaitObject(handles[index]);
    if (objects[index] == nullptr) {
      tLastError = ERROR_INVALID_HANDLE;
      return WAIT_FAILED;
    }
  }
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
  for (;;) {
    if (waitAll != FALSE) {
      bool all = true;
      for (DWORD index = 0; index < count && all; ++index) {
        std::lock_guard<std::mutex> lock(objects[index]->mutex);
        all = objects[index]->ReadyLocked();
      }
      if (all) {
        for (DWORD index = 0; index < count; ++index) {
          std::lock_guard<std::mutex> lock(objects[index]->mutex);
          objects[index]->AcquireLocked();
        }
        return WAIT_OBJECT_0;
      }
    } else {
      for (DWORD index = 0; index < count; ++index) {
        WaitObject* const object = objects[index].get();
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

BOOL CloseHandle(
  const HANDLE handle
)
{
  if (handle == kCurrentThreadPseudoHandle || handle == kCurrentProcessPseudoHandle) {
    return TRUE;
  }
  std::shared_ptr<ShimHandle> object; // released after the lock: a file closes its descriptor then
  {
    HandleTable& table = Handles();
    const std::unique_lock lock(table.lock);
    const auto found = table.handles.find(handle);
    if (found == table.handles.end()) {
      tLastError = ERROR_INVALID_HANDLE;
      return FALSE;
    }
    object = std::move(found->second);
    table.handles.erase(found);
  }
  return TRUE;
}

void InitializeCriticalSection(
  CRITICAL_SECTION* const section
)
{
  pthread_mutexattr_t attributes;
  (void)::pthread_mutexattr_init(&attributes);
  (void)::pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
  (void)::pthread_mutex_init(SectionMutex(section), &attributes);
  (void)::pthread_mutexattr_destroy(&attributes);
  section->initialized = true;
}

BOOL InitializeCriticalSectionAndSpinCount(
  CRITICAL_SECTION* const section,
  DWORD
)
{
  InitializeCriticalSection(section);
  return TRUE;
}

void EnterCriticalSection(
  CRITICAL_SECTION* const section
)
{
  (void)::pthread_mutex_lock(SectionMutex(section));
}

BOOL TryEnterCriticalSection(
  CRITICAL_SECTION* const section
)
{
  return ::pthread_mutex_trylock(SectionMutex(section)) == 0 ? TRUE : FALSE;
}

void LeaveCriticalSection(
  CRITICAL_SECTION* const section
)
{
  (void)::pthread_mutex_unlock(SectionMutex(section));
}

void DeleteCriticalSection(
  CRITICAL_SECTION* const section
)
{
  if (section->initialized) {
    (void)::pthread_mutex_destroy(SectionMutex(section));
    section->initialized = false;
  }
}

// --- Threads, processes and time ---------------------------------------------------------

DWORD GetCurrentThreadId()
{
  return static_cast<DWORD>(platform::posix::CurrentThreadId());
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

void Sleep(
  const DWORD milliseconds
)
{
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

DWORD SleepEx(
  const DWORD milliseconds,
  const BOOL alertable
)
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
    const auto hasCalls = [&queue] {
      return !queue.calls.empty();
    };
    if (milliseconds == INFINITE) {
      queue.queued.wait(lock, hasCalls);
    } else if (!queue.queued.wait_for(lock, std::chrono::milliseconds(milliseconds), hasCalls)) {
      return 0;
    }
  }
  (void)RunQueuedApcs();
  return WAIT_IO_COMPLETION;
}

HANDLE OpenThread(
  DWORD,
  BOOL,
  const DWORD threadId
)
{
  if (!platform::posix::ThreadExists(threadId)) {
    tLastError = ERROR_INVALID_PARAMETER;
    return nullptr;
  }
  const auto thread = std::make_shared<ThreadObject>();
  thread->threadId = threadId;
  thread->queue = ApcQueueOf(threadId);
  return Register(thread);
}

DWORD QueueUserAPC(
  const PAPCFUNC function,
  const HANDLE threadHandle,
  const ULONG_PTR data
)
{
  const std::shared_ptr<ShimHandle> object = AsShimHandle(threadHandle);
  std::shared_ptr<ApcQueue> queue;
  if (threadHandle == kCurrentThreadPseudoHandle) {
    queue = ApcQueueOf(static_cast<DWORD>(platform::posix::CurrentThreadId()));
  } else if (object != nullptr && object->kind == ShimHandle::Kind::Thread) {
    queue = static_cast<ThreadObject*>(object.get())->queue;
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

HMODULE GetModuleHandleA(
  const char* const moduleName
)
{
  void* const module = ::dlopen(moduleName, RTLD_NOW | RTLD_NOLOAD);
  if (module != nullptr) {
    (void)::dlclose(module); // GetModuleHandle takes no reference.
  }
  return module;
}

HMODULE GetModuleHandleW(
  const wchar_t* const moduleName
)
{
  if (moduleName == nullptr) {
    return static_cast<HMODULE>(platform::posix::ExecutableImageBase());
  }
  return GetModuleHandleA(NarrowPath(moduleName).c_str());
}

BOOL InitOnceExecuteOnce(
  const PINIT_ONCE initOnce,
  const PINIT_ONCE_FN function,
  const PVOID parameter,
  PVOID* const context
)
{
  for (;;) {
    int state = __atomic_load_n(&initOnce->state, __ATOMIC_ACQUIRE);
    if (state == 2) {
      return TRUE;
    }
    if (
      state == 0 && __atomic_compare_exchange_n(&initOnce->state, &state, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
    ) {
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
    char raw[8192];
    const std::size_t got = platform::posix::ReadArguments(raw, sizeof(raw) - 1);
    std::size_t out = 0;
    for (std::size_t at = 0; at < got && out + 1 < sizeof(sCommandLine) / sizeof(sCommandLine[0]); ++at) {
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

const char* GetCommandLineA()
{
  // The same line, byte for byte (the arguments are UTF-8 already).
  static char sCommandLine[8192];
  static INIT_ONCE sOnce = INIT_ONCE_STATIC_INIT;
  (void)InitOnceExecuteOnce(&sOnce, [](PINIT_ONCE, PVOID, PVOID*) -> BOOL {
    char raw[8192];
    const std::size_t got = platform::posix::ReadArguments(raw, sizeof(raw) - 1);
    std::size_t out = 0;
    for (std::size_t at = 0; at < got && out + 1 < sizeof(sCommandLine); ++at) {
      if (raw[at] == '\0') {
        if (at + 1 < got) {
          sCommandLine[out++] = ' ';
        }
      } else {
        sCommandLine[out++] = raw[at];
      }
    }
    sCommandLine[out] = '\0';
    return TRUE;
  }, nullptr, nullptr);
  return sCommandLine;
}

HANDLE GetProcessHeap()
{
  static int sProcessHeap = 0;
  return &sProcessHeap;
}

HANDLE HeapCreate(
  DWORD,
  SIZE_T,
  SIZE_T
)
{
  return GetProcessHeap();
}

void* HeapAlloc(
  HANDLE,
  const DWORD flags,
  const SIZE_T bytes
)
{
  void* const block =
    (flags & HEAP_ZERO_MEMORY) != 0 ? std::calloc(1, bytes != 0 ? bytes : 1) : std::malloc(bytes != 0 ? bytes : 1);
  if (block == nullptr) {
    tLastError = ERROR_NOT_ENOUGH_MEMORY;
  }
  return block;
}

BOOL HeapFree(
  HANDLE,
  DWORD,
  void* const memory
)
{
  std::free(memory);
  return TRUE;
}

SIZE_T HeapSize(
  HANDLE,
  DWORD,
  const void* const memory
)
{
  return memory != nullptr ? platform::posix::AllocationSize(memory) : static_cast<SIZE_T>(-1);
}

HMODULE LoadLibraryA(
  const char* const fileName
)
{
  void* const module = ::dlopen(fileName, RTLD_NOW | RTLD_LOCAL);
  if (module == nullptr) {
    tLastError = ERROR_FILE_NOT_FOUND;
  }
  return module;
}

void* GetProcAddress(
  const HMODULE module,
  const char* const procName
)
{
  return module != nullptr ? ::dlsym(module, procName) : nullptr;
}

BOOL FreeLibrary(
  const HMODULE module
)
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

ULONGLONG GetTickCount64()
{
  timespec now{};
  ::clock_gettime(CLOCK_MONOTONIC, &now);
  return static_cast<ULONGLONG>(now.tv_sec) * 1000u + static_cast<ULONGLONG>(now.tv_nsec) / 1000000u;
}

BOOL QueryPerformanceCounter(
  LARGE_INTEGER* const count
)
{
  timespec now{};
  ::clock_gettime(CLOCK_MONOTONIC, &now);
  count->QuadPart = static_cast<std::int64_t>(now.tv_sec) * 1000000000LL + static_cast<std::int64_t>(now.tv_nsec);
  return TRUE;
}

BOOL QueryPerformanceFrequency(
  LARGE_INTEGER* const frequency
)
{
  frequency->QuadPart = 1000000000LL; // QueryPerformanceCounter counts nanoseconds here
  return TRUE;
}

void GetSystemInfo(
  SYSTEM_INFO* const info
)
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

BOOL TerminateProcess(
  const HANDLE process,
  const UINT exitCode
)
{
  // Only this process is ever named (GetCurrentProcess's pseudo-handle).
  if (process != GetCurrentProcess()) {
    tLastError = ERROR_INVALID_HANDLE;
    return FALSE;
  }
  std::_Exit(static_cast<int>(exitCode));
}

BOOL GetVersionExW(
  OSVERSIONINFOW* const info
)
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

void SetLastError(
  const DWORD error
)
{
  tLastError = error;
}

/// A kernel CPU list such as "0-7,16-23" from a sysfs file; CPUs above 63 are left out, and an unreadable file is 0.
BOOL GetProcessAffinityMask(
  HANDLE,
  DWORD_PTR* const processMask,
  DWORD_PTR* const systemMask
)
{
  if (processMask != nullptr) {
    *processMask = static_cast<DWORD_PTR>(platform::posix::ProcessCpuMask());
  }
  if (systemMask != nullptr) {
    *systemMask = static_cast<DWORD_PTR>(platform::posix::OnlineCpuMask());
  }
  return TRUE;
}

DWORD GetEnvironmentVariableA(
  const char* const name,
  char* const buffer,
  const DWORD size
)
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

void OutputDebugStringA(
  const char* const text
)
{
  if (text != nullptr) {
    (void)std::fputs(text, stderr);
  }
}

void OutputDebugStringW(
  const wchar_t* const text
)
{
  if (text != nullptr) {
    (void)std::fputs(NarrowPath(text).c_str(), stderr);
  }
}

BOOL SetThreadPriority(
  HANDLE,
  int
)
{
  // A scheduling hint; the server keeps the default policy.
  return TRUE;
}

DWORD_PTR SetThreadAffinityMask(
  const HANDLE thread,
  const DWORD_PTR mask
)
{
  if (thread != kCurrentThreadPseudoHandle || mask == 0) {
    tLastError = ERROR_INVALID_PARAMETER;
    return 0;
  }
  const std::uint64_t previous = platform::posix::SetThreadCpuMask(mask);
  if (previous == 0) {
    tLastError = ERROR_INVALID_PARAMETER;
    return 0;
  }
  return static_cast<DWORD_PTR>(previous);
}

BOOL GetLogicalProcessorInformationEx(
  const LOGICAL_PROCESSOR_RELATIONSHIP relation,
  SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* const buffer,
  DWORD* const length
)
{
  if (length == nullptr) {
    tLastError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  // One record per physical core or per NUMA node, read from sysfs. CPUs above 63 are outside group 0.
  std::vector<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX> records;
  const auto addRecord = [&records, relation](const DWORD_PTR mask, const DWORD node) {
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX record{};
    record.Relationship = relation;
    record.Size = static_cast<DWORD>(sizeof(record));
    if (relation == RelationProcessorCore) {
      record.Processor.GroupCount = 1;
      record.Processor.GroupMask[0].Mask = mask;
    } else {
      record.NumaNode.NodeNumber = node;
      record.NumaNode.GroupCount = 1;
      record.NumaNode.GroupMask.Mask = mask;
    }
    records.push_back(record);
  };
  if (relation == RelationProcessorCore) {
    for (const std::uint64_t core : platform::posix::CoreCpuMasks()) {
      addRecord(static_cast<DWORD_PTR>(core), 0);
    }
  } else if (relation == RelationNumaNode) {
    const std::vector<std::uint64_t> nodes = platform::posix::NumaNodeCpuMasks();
    for (DWORD node = 0; node < nodes.size(); ++node) {
      if (nodes[node] != 0) {
        addRecord(static_cast<DWORD_PTR>(nodes[node]), node);
      }
    }
  }
  const DWORD needed = static_cast<DWORD>(records.size() * sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX));
  if (needed == 0) {
    *length = 0;
    tLastError = ERROR_NOT_SUPPORTED;
    return FALSE;
  }
  if (buffer == nullptr || *length < needed) {
    *length = needed;
    tLastError = ERROR_INSUFFICIENT_BUFFER;
    return FALSE;
  }
  std::memcpy(static_cast<void*>(buffer), records.data(), needed);
  *length = needed;
  return TRUE;
}

// --- Memory ------------------------------------------------------------------------------

LPVOID VirtualAlloc(
  const LPVOID address,
  const SIZE_T size,
  const DWORD allocationType,
  const DWORD protect
)
{
  const int protection = protect == PAGE_NOACCESS ? PROT_NONE
    : protect == PAGE_READONLY                    ? PROT_READ
                                                  : (PROT_READ | PROT_WRITE);
  if (address != nullptr && (allocationType & MEM_COMMIT) != 0 && (allocationType & MEM_RESERVE) == 0) {
    // Commit within a reservation.
    return ::mprotect(address, size, protection) == 0 ? address : nullptr;
  }
  void* const mapped = ::mmap(
    address, size, (allocationType & MEM_COMMIT) != 0 ? protection : PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
  );
  if (mapped == MAP_FAILED) {
    SetErrnoError();
    return nullptr;
  }
  return mapped;
}

BOOL VirtualFree(
  const LPVOID address,
  const SIZE_T size,
  const DWORD freeType
)
{
  if ((freeType & MEM_RELEASE) != 0) {
    // MEM_RELEASE passes size 0 on Windows; the reservation's size is not known here.
    return size != 0 && ::munmap(address, size) == 0 ? TRUE : FALSE;
  }
  return ::mprotect(address, size, PROT_NONE) == 0 ? TRUE : FALSE;
}

SIZE_T VirtualQuery(
  const LPCVOID address,
  MEMORY_BASIC_INFORMATION* const info,
  const SIZE_T length
)
{
  if (info == nullptr || length < sizeof(MEMORY_BASIC_INFORMATION)) {
    return 0;
  }
  if (const auto region = platform::posix::FindMemoryRegion(reinterpret_cast<std::uintptr_t>(address))) {
    *info = MEMORY_BASIC_INFORMATION{};
    info->BaseAddress = reinterpret_cast<LPVOID>(region->begin);
    info->AllocationBase = reinterpret_cast<LPVOID>(region->begin);
    info->RegionSize = region->end - region->begin;
    info->State = region->readable ? MEM_COMMIT : MEM_RESERVE;
    info->Protect = !region->readable ? PAGE_NOACCESS : region->writable ? PAGE_READWRITE : PAGE_READONLY;
    info->AllocationProtect = info->Protect;
    info->Type = region->isPrivate ? MEM_PRIVATE : 0u;
    return sizeof(MEMORY_BASIC_INFORMATION);
  }
  *info = MEMORY_BASIC_INFORMATION{};
  info->BaseAddress = const_cast<LPVOID>(address);
  info->State = MEM_FREE;
  info->Protect = PAGE_NOACCESS;
  return sizeof(MEMORY_BASIC_INFORMATION);
}

HLOCAL LocalFree(
  const HLOCAL memory
)
{
  std::free(memory);
  return nullptr;
}

// --- Files -------------------------------------------------------------------------------

HANDLE CreateFileA(
  const char* const path,
  const DWORD desiredAccess,
  DWORD,
  void*,
  const DWORD creation,
  DWORD,
  HANDLE
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
  const auto file = std::make_shared<FileObject>();
  file->fd = fd;
  tLastError = ERROR_SUCCESS;
  return Register(file);
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

BOOL ReadFile(
  const HANDLE handle,
  void* const buffer,
  const DWORD bytesToRead,
  DWORD* const bytesRead,
  void*
)
{
  const std::shared_ptr<FileObject> file = AsFileObject(handle);
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

BOOL WriteFile(
  const HANDLE handle,
  const void* const buffer,
  const DWORD bytesToWrite,
  DWORD* const bytesWritten,
  void*
)
{
  const std::shared_ptr<FileObject> file = AsFileObject(handle);
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

BOOL SetFilePointerEx(
  const HANDLE handle,
  const LARGE_INTEGER distance,
  LARGE_INTEGER* const newPosition,
  const DWORD moveMethod
)
{
  const std::shared_ptr<FileObject> file = AsFileObject(handle);
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

DWORD SetFilePointer(
  const HANDLE handle,
  const LONG distance,
  LONG* const distanceHigh,
  const DWORD moveMethod
)
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

BOOL GetFileSizeEx(
  const HANDLE handle,
  LARGE_INTEGER* const size
)
{
  const std::shared_ptr<FileObject> file = AsFileObject(handle);
  struct stat status{};
  if (file == nullptr || ::fstat(file->fd, &status) != 0) {
    tLastError = ERROR_INVALID_HANDLE;
    return FALSE;
  }
  size->QuadPart = static_cast<std::int64_t>(status.st_size);
  return TRUE;
}

DWORD GetFileSize(
  const HANDLE handle,
  DWORD* const sizeHigh
)
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
  const HANDLE file,
  void*,
  const DWORD protect,
  const DWORD maximumSizeHigh,
  const DWORD maximumSizeLow,
  const wchar_t*
)
{
  const std::shared_ptr<FileObject> source = AsFileObject(file);
  struct stat status{};
  if (
    source == nullptr || protect != PAGE_READONLY || maximumSizeHigh != 0 || maximumSizeLow != 0 ||
    ::fstat(source->fd, &status) != 0
  ) {
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
  const auto mapping = std::make_shared<MappingObject>();
  mapping->fd = fd;
  mapping->size = static_cast<std::size_t>(status.st_size);
  tLastError = ERROR_SUCCESS;
  return Register(mapping);
}

void* MapViewOfFile(
  const HANDLE mappingHandle,
  const DWORD desiredAccess,
  const DWORD offsetHigh,
  const DWORD offsetLow,
  const std::size_t bytes
)
{
  const std::shared_ptr<ShimHandle> object = AsShimHandle(mappingHandle);
  if (
    object == nullptr || object->kind != ShimHandle::Kind::Mapping || desiredAccess != FILE_MAP_READ ||
    offsetHigh != 0 || offsetLow != 0
  ) {
    tLastError = ERROR_INVALID_PARAMETER;
    return nullptr;
  }
  const auto* const mapping = static_cast<const MappingObject*>(object.get());
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

BOOL UnmapViewOfFile(
  const void* const view
)
{
  std::size_t length = 0;
  {
    const std::lock_guard<std::mutex> lock(gViewLock);
    const auto found = std::find_if(gViews.begin(), gViews.end(), [view](const auto& entry) {
      return entry.first == view;
    });
    if (found == gViews.end()) {
      tLastError = ERROR_INVALID_PARAMETER;
      return FALSE;
    }
    length = found->second;
    gViews.erase(found);
  }
  return ::munmap(const_cast<void*>(view), length) == 0 ? TRUE : FALSE;
}

BOOL FlushFileBuffers(
  const HANDLE handle
)
{
  const std::shared_ptr<FileObject> file = AsFileObject(handle);
  return file != nullptr && ::fsync(file->fd) == 0 ? TRUE : FALSE;
}

BOOL SetEndOfFile(
  const HANDLE handle
)
{
  const std::shared_ptr<FileObject> file = AsFileObject(handle);
  if (file == nullptr) {
    return FALSE;
  }
  const off_t position = ::lseek(file->fd, 0, SEEK_CUR);
  return position >= 0 && ::ftruncate(file->fd, position) == 0 ? TRUE : FALSE;
}

DWORD GetFileAttributesA(
  const char* const path
)
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

DWORD GetFileAttributesW(
  const wchar_t* const path
)
{
  return GetFileAttributesA(NarrowPath(path).c_str());
}

BOOL MoveFileExW(
  const wchar_t* const from,
  const wchar_t* const to,
  const DWORD flags
)
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

BOOL MoveFileExA(
  const char* const from,
  const char* const to,
  const DWORD flags
)
{
  const std::string source = SlashPath(from);
  const std::string target = SlashPath(to);
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

BOOL CopyFileW(
  const wchar_t* const from,
  const wchar_t* const to,
  const BOOL failIfExists
)
{
  const std::filesystem::path source = ResolveCase(NarrowPath(from));
  const std::filesystem::path target = ResolveCase(NarrowPath(to));
  std::error_code error;
  const auto options =
    failIfExists ? std::filesystem::copy_options::none : std::filesystem::copy_options::overwrite_existing;
  if (!std::filesystem::copy_file(source, target, options, error)) {
    tLastError = error ? ErrnoToWin32(error.value()) : ERROR_ALREADY_EXISTS;
    return FALSE;
  }
  return TRUE;
}

BOOL MoveFileW(
  const wchar_t* const from,
  const wchar_t* const to
)
{
  return MoveFileExW(from, to, 0);
}

BOOL DeleteFileA(
  const char* const path
)
{
  if (::unlink(SlashPath(path).c_str()) != 0) {
    SetErrnoError();
    return FALSE;
  }
  return TRUE;
}

BOOL DeleteFileW(
  const wchar_t* const path
)
{
  return DeleteFileA(NarrowPath(path).c_str());
}

BOOL CreateDirectoryW(
  const wchar_t* const path,
  void*
)
{
  if (::mkdir(ResolveCase(NarrowPath(path)).c_str(), 0755) != 0) {
    SetErrnoError();
    return FALSE;
  }
  return TRUE;
}

BOOL ReplaceFileW(
  const wchar_t* const replacedFile,
  const wchar_t* const replacementFile,
  const wchar_t* const backupFile,
  DWORD,
  void*,
  void*
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

BOOL CreateDirectoryA(
  const char* const path,
  void*
)
{
  if (::mkdir(SlashPath(path).c_str(), 0755) != 0) {
    SetErrnoError();
    return FALSE;
  }
  return TRUE;
}

void FAF_SetPathSpellingTrace(
  std::FILE* const file
)
{
  sPathSpellingTrace.store(file, std::memory_order_relaxed);
}

char* _fullpath(
  char* const absolutePath,
  const char* const relativePath,
  const std::size_t maxLength
)
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
  UINT,
  DWORD,
  const wchar_t* const wide,
  const int wideLength,
  char* const multiByte,
  const int multiByteLength,
  const char*,
  BOOL* const usedDefaultChar
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
  UINT,
  DWORD,
  const char* const multiByte,
  const int multiByteLength,
  wchar_t* const wide,
  const int wideLength
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

BOOL PathFileExistsW(
  const wchar_t* const path
)
{
  return ::access(ResolveCase(NarrowPath(path)).c_str(), F_OK) == 0 ? TRUE : FALSE;
}

DWORD GetModuleFileNameW(
  const HMODULE module,
  wchar_t* const fileName,
  const DWORD size
)
{
  if (module != nullptr || fileName == nullptr || size == 0) {
    tLastError = ERROR_INVALID_PARAMETER;
    return 0;
  }
  const std::string exe = platform::posix::ExecutablePath();
  if (exe.empty()) {
    SetErrnoError();
    return 0;
  }
  const std::wstring wide = WidenUtf8(exe);
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

BOOL SetProcessAffinityMask(
  const HANDLE process,
  const DWORD_PTR processMask
)
{
  if (process != kCurrentProcessPseudoHandle || processMask == 0) {
    tLastError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  if (!platform::posix::SetProcessCpuMask(processMask)) {
    SetErrnoError();
    return FALSE;
  }
  return TRUE;
}

namespace
{
  /**
   * The folder xdg-user-dirs names for `key` (XDG_DOCUMENTS_DIR, XDG_DESKTOP_DIR), read as
   * `xdg-user-dir` reads it: `<configHome>/user-dirs.dirs` holds shell lines KEY="$HOME/<path>" or
   * KEY="/<path>", and the last one wins. A desktop in another language names its own folder there
   * (~/Dokumente, ~/Bureau). Empty when there is no such file or line; the environment variable of
   * the same name comes next, as `xdg-user-dir` falls back to it.
   */
  [[nodiscard]] std::string XdgUserDirectory(
    const std::string& home,
    const std::string& configHome,
    const char* const key
  )
  {
    std::string found;
    const std::string prefix = std::string(key) + "=";
    std::ifstream file(configHome + "/user-dirs.dirs");
    for (std::string line; std::getline(file, line);) {
      const std::size_t start = line.find_first_not_of(" \t");
      if (start == std::string::npos || line.compare(start, prefix.size(), prefix) != 0) {
        continue;
      }
      std::string value = line.substr(start + prefix.size());
      while (!value.empty() && (value.back() == '\r' || value.back() == ' ' || value.back() == '\t')) {
        value.pop_back();
      }
      if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
      }
      if (value.starts_with("$HOME") && (value.size() == 5 || value[5] == '/')) {
        found = home + value.substr(5);
      } else if (!value.empty() && value[0] == '/') {
        found = value;
      }
    }
    if (found.empty()) {
      const char* const environment = std::getenv(key);
      if (environment != nullptr && environment[0] == '/') {
        found = environment;
      }
    }
    while (found.size() > 1 && found.back() == '/') {
      found.pop_back();
    }
    return found;
  }
} // namespace

HRESULT SHGetFolderPathW(
  HWND,
  const int folder,
  HANDLE,
  DWORD,
  wchar_t* const path
)
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
  const auto userDirectory = [&](const char* const key, const char* const fallback) {
    const std::string named = XdgUserDirectory(home, fromEnvironment("XDG_CONFIG_HOME", "/.config"), key);
    return named.empty() ? std::string(home) + fallback : named;
  };
  const int kind = folder & ~CSIDL_FLAG_CREATE;
  std::string resolved;
  switch (kind) {
#if FAFRE_PLATFORM_MACOS // ~/Library/Application Support: macOS has no XDG folders
  case CSIDL_LOCAL_APPDATA:
  case CSIDL_APPDATA:
    // Both of Windows' application data folders are the one macOS has; the caches go to
    // ~/Library/Caches instead (platform/CacheFolder.h).
    resolved = std::string(home) + "/Library/Application Support";
    break;
#else
  case CSIDL_LOCAL_APPDATA:
    resolved = fromEnvironment("XDG_DATA_HOME", "/.local/share");
    break;
  case CSIDL_APPDATA:
    resolved = fromEnvironment("XDG_CONFIG_HOME", "/.config");
    break;
#endif
  case CSIDL_PERSONAL:
    resolved = userDirectory("XDG_DOCUMENTS_DIR", "/Documents");
    break;
  case CSIDL_DESKTOP:
  case CSIDL_DESKTOPDIRECTORY:
    resolved = userDirectory("XDG_DESKTOP_DIR", "/Desktop");
    break;
  default:
    return E_FAIL;
  }
  const std::wstring wide = WidenUtf8(resolved);
  if (wide.size() >= MAX_PATH) {
    return E_FAIL;
  }
  // Windows' known folders always exist, and callers create only their own subfolders below them
  // (the replay and saved-game folders, one level at a time); a home folder here may have no
  // ~/.local/share or the documents folder (a fresh account, a container). The folders the engine
  // writes below are made here; the desktop, which only Lua's SHGetFolderPath("DESKTOP") asks for,
  // only with CSIDL_FLAG_CREATE, as Windows creates a missing folder only then.
  const bool engineWritesBelow = kind == CSIDL_LOCAL_APPDATA || kind == CSIDL_APPDATA || kind == CSIDL_PERSONAL;
  if (engineWritesBelow || (folder & CSIDL_FLAG_CREATE) != 0) {
    std::error_code created;
    std::filesystem::create_directories(resolved, created);
  }
  std::wmemcpy(path, wide.c_str(), wide.size() + 1);
  return S_OK;
}

namespace
{
  /// A path as a `file://` URL's path: every byte but unreserved characters and '/' as %XX.
  [[nodiscard]] std::string TrashInfoPath(
    const std::string& path
  )
  {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (const char c : path) {
      const auto byte = static_cast<unsigned char>(c);
      if (std::isalnum(byte) != 0 || c == '/' || c == '-' || c == '_' || c == '.' || c == '~') {
        out.push_back(c);
      } else {
        out.push_back('%');
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 0x0Fu]);
      }
    }
    return out;
  }

  enum class TrashMove
  {
    Moved,
    OtherFileSystem, // the trash is on another file system than the entry
    Failed,
  };

  /**
   * Moves `absolute` into the trash folder `trash` of the freedesktop.org Trash specification: to
   * <trash>/files under a free name, with <trash>/info/<name>.trashinfo holding `infoPath` (where it
   * came from) and the time, which file managers restore it from. With `copyAcrossMounts`, an entry
   * the rename can't move there (another mount of the same file system: a sandbox's or container's
   * bind mount) is copied there and then removed.
   */
  [[nodiscard]] TrashMove MoveIntoTrash(
    const std::string& trash,
    const std::string& absolute,
    const std::string& infoPath,
    const bool copyAcrossMounts = false
  )
  {
    std::error_code error;
    std::filesystem::create_directories(trash + "/files", error);
    std::filesystem::create_directories(trash + "/info", error);
    const std::string leaf = absolute.substr(absolute.rfind('/') + 1);
    if (leaf.empty()) {
      return TrashMove::Failed;
    }

    char deletedAt[32]{};
    const std::time_t now = std::time(nullptr);
    std::tm local{};
    (void)::localtime_r(&now, &local);
    (void)std::strftime(deletedAt, sizeof(deletedAt), "%Y-%m-%dT%H:%M:%S", &local);
    const std::string info = "[Trash Info]\nPath=" + TrashInfoPath(infoPath) + "\nDeletionDate=" + deletedAt + "\n";

    for (int attempt = 1; attempt < 10000; ++attempt) {
      const std::string name = attempt == 1 ? leaf : leaf + "." + std::to_string(attempt);
      // The info file is made first and exclusively: it claims the name (the specification's order).
      const std::string infoFile = trash + "/info/" + name + ".trashinfo";
      const int fd = ::open(infoFile.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
      if (fd < 0) {
        if (errno == EEXIST) {
          continue;
        }
        return TrashMove::Failed;
      }
      const bool written = ::write(fd, info.data(), info.size()) == static_cast<ssize_t>(info.size());
      (void)::close(fd);
      if (!written) {
        (void)::unlink(infoFile.c_str());
        return TrashMove::Failed;
      }
      const std::string target = trash + "/files/" + name;
      if (::access(target.c_str(), F_OK) == 0) {
        // A file left there with no info file: the name stays taken.
        (void)::unlink(infoFile.c_str());
        continue;
      }
      if (::rename(absolute.c_str(), target.c_str()) == 0) {
        return TrashMove::Moved;
      }
      const int renameError = errno;
      if (renameError == EXDEV && copyAcrossMounts) {
        std::filesystem::copy(
          absolute,
          target,
          std::filesystem::copy_options::recursive | std::filesystem::copy_options::copy_symlinks,
          error
        );
        if (!error) {
          // A copy gets new times; a restored save or replay keeps its own (the dialogs show them).
          const std::filesystem::path from(absolute);
          const std::filesystem::path to(target);
          const auto keepTime = [](const std::filesystem::path& source, const std::filesystem::path& copy) {
            std::error_code timeError;
            if (!std::filesystem::is_symlink(source, timeError)) {
              const auto time = std::filesystem::last_write_time(source, timeError);
              if (!timeError) {
                std::filesystem::last_write_time(copy, time, timeError);
              }
            }
          };
          std::error_code walkError;
          if (std::filesystem::is_directory(from, walkError)) {
            for (std::filesystem::recursive_directory_iterator walk(from, walkError), done; !walkError && walk != done;
                 walk.increment(walkError)) {
              keepTime(walk->path(), to / walk->path().lexically_relative(from));
            }
          }
          keepTime(from, to);
          (void)std::filesystem::remove_all(absolute, error);
          if (!error) {
            return TrashMove::Moved;
          }
          // Part of it couldn't be removed: the copy in the trash stays, and so does what's left.
          return TrashMove::Failed;
        }
        std::error_code ignored;
        (void)std::filesystem::remove_all(target, ignored);
      }
      (void)::unlink(infoFile.c_str());
      return renameError == EXDEV ? TrashMove::OtherFileSystem : TrashMove::Failed;
    }
    return TrashMove::Failed;
  }

  /**
   * The mount points of the process's mount table (/proc/self/mountinfo). A bind mount (a
   * container's or a sandbox's home) is a mount point of its own there, though its files share the
   * device of the file system it shows. Empty when there is no table (not Linux).
   */
  [[nodiscard]] std::vector<std::string> MountPoints()
  {
    return platform::posix::MountPoints();
  }

  /// Whether `folder` is `point`'s folder or `point` itself is below `folder`.
  [[nodiscard]] bool IsBelow(
    const std::string& point,
    const std::string& folder
  )
  {
    return folder == "/"
      ? point != "/"
      : point.size() > folder.size() && point.compare(0, folder.size(), folder) == 0 && point[folder.size()] == '/';
  }

  /// The mount point holding `absolute`: the longest one of the mount table that is a folder of it.
  [[nodiscard]] std::string MountPointOf(
    const std::string& absolute
  )
  {
    std::string best;
    for (const std::string& point : MountPoints()) {
      if ((point == "/" || IsBelow(absolute, point)) && point.size() > best.size()) {
        best = point;
      }
    }
    return best;
  }

  /// Whether a file system is mounted at `real` (resolved, no trailing '/') or anywhere below it.
  [[nodiscard]] bool HoldsAMount(
    const std::string& real
  )
  {
    for (const std::string& point : MountPoints()) {
      if (point == real || IsBelow(point, real)) {
        return true;
      }
    }
    return false;
  }

  /**
   * The folder holding `absolute` that is the top of its device, found by walking up while the
   * device stays the same: a btrfs subvolume that isn't mounted on its own has a device of its own
   * inside its mount, and a rename only stays within it.
   */
  [[nodiscard]] std::string DeviceTopOf(
    const std::string& absolute
  )
  {
    struct stat entry{};
    if (::lstat(absolute.c_str(), &entry) != 0) {
      return {};
    }
    std::string folder = absolute.substr(0, absolute.rfind('/'));
    if (folder.empty()) {
      return "/";
    }
    struct stat at{};
    if (::stat(folder.c_str(), &at) != 0 || at.st_dev != entry.st_dev) {
      // The entry is a mount point itself; it has no trash of its own file system to go to.
      return {};
    }
    while (!folder.empty()) {
      const std::size_t slash = folder.rfind('/');
      const std::string parent = slash == 0 ? std::string("/") : folder.substr(0, slash);
      struct stat above{};
      if (::stat(parent.c_str(), &above) != 0 || above.st_dev != entry.st_dev) {
        return folder;
      }
      if (parent == "/") {
        return parent;
      }
      folder = parent;
    }
    return "/";
  }

  /// A folder the user owns, made with mode 0700 when missing; false for a symbolic link or another's.
  [[nodiscard]] bool OwnTrashFolder(
    const std::string& folder
  )
  {
    (void)::mkdir(folder.c_str(), 0700);
    struct stat info{};
    return ::lstat(folder.c_str(), &info) == 0 && S_ISDIR(info.st_mode) && info.st_uid == ::getuid();
  }

  /**
   * The trash of the file system `top` is the top of, as the specification names it: $top/.Trash/$uid
   * when $top/.Trash is a real folder with the sticky bit (an administrator's shared trash), else
   * $top/.Trash-$uid. Empty when neither can be used (no write access, a link planted there).
   */
  [[nodiscard]] std::string TopDirectoryTrash(
    const std::string& top
  )
  {
    const std::string base = top == "/" ? std::string() : top;
    const std::string uid = std::to_string(::getuid());
    struct stat shared{};
    if (
      ::lstat((base + "/.Trash").c_str(), &shared) == 0 && S_ISDIR(shared.st_mode) && (shared.st_mode & S_ISVTX) != 0 &&
      OwnTrashFolder(base + "/.Trash/" + uid)
    ) {
      return base + "/.Trash/" + uid;
    }
    if (OwnTrashFolder(base + "/.Trash-" + uid)) {
      return base + "/.Trash-" + uid;
    }
    return {};
  }

  /**
   * FOF_ALLOWUNDO's recycle bin on a desktop: the freedesktop.org Trash specification, where file
   * managers list and restore it. An entry goes to the home trash ($XDG_DATA_HOME/Trash, else
   * ~/.local/share/Trash) when that is on its file system, else to the trash at the top of its own
   * file system (a second disk, a USB stick), which names it relative to that top. False when
   * neither takes it, and the caller deletes it then, as Windows does on a drive with no recycle bin.
   */
  [[nodiscard]] bool MoveToTrash(
    const std::string& path
  )
  {
    std::string absolute = path;
    std::error_code error;
    if (absolute.empty() || absolute[0] != '/') {
      absolute = std::filesystem::absolute(path, error).string();
    }
    while (absolute.size() > 1 && absolute.back() == '/') {
      absolute.pop_back();
    }
    // The folder as it is on disk (links resolved), so the info file names where it really was.
    const std::size_t slash = absolute.rfind('/');
    const std::string folder = slash == 0 ? std::string("/") : absolute.substr(0, slash);
    if (char* const real = ::realpath(folder.c_str(), nullptr)) {
      const std::string realFolder = real;
      std::free(real);
      absolute = (realFolder == "/" ? std::string() : realFolder) + absolute.substr(slash);
    }

    const char* const home = std::getenv("HOME");
    const char* const dataHome = std::getenv("XDG_DATA_HOME");
    std::string homeTrash;
    if (dataHome != nullptr && dataHome[0] == '/') {
      homeTrash = std::string(dataHome) + "/Trash";
    } else if (home != nullptr && home[0] == '/') {
      homeTrash = std::string(home) + "/.local/share/Trash";
    }
    if (!homeTrash.empty()) {
      std::filesystem::create_directories(homeTrash, error);
      std::filesystem::permissions(homeTrash, std::filesystem::perms::owner_all, error);
      // The home trash's file system is that of the nearest part of its path that exists.
      std::string homeAt = homeTrash;
      struct stat homeInfo{};
      while (::stat(homeAt.c_str(), &homeInfo) != 0 && homeAt.size() > 1) {
        const std::size_t up = homeAt.rfind('/');
        homeAt = up == 0 || up == std::string::npos ? std::string("/") : homeAt.substr(0, up);
      }
      struct stat entryInfo{};
      const bool sameFileSystem = ::lstat(absolute.c_str(), &entryInfo) == 0 &&
        ::stat(homeAt.c_str(), &homeInfo) == 0 && homeInfo.st_dev == entryInfo.st_dev;
      // An entry on the home trash's file system goes there even through another mount of it (a
      // sandbox's bind mount), by a copy; a trash at the bind point would be hidden from the desktop.
      const TrashMove moved = MoveIntoTrash(homeTrash, absolute, absolute, sameFileSystem);
      if (moved == TrashMove::Moved) {
        return true;
      }
      // A home trash that can't take it (read-only, full, not a folder) only ends here for an entry
      // on its own file system; one on another disk still has that disk's trash.
      if (sameFileSystem) {
        return false;
      }
    }

    // The trash at the top of its file system: its mount point, and where the rename can't reach
    // that (a btrfs subvolume inside the mount), the top of its own device.
    const std::string mountTop = MountPointOf(absolute);
    const std::string deviceTop = DeviceTopOf(absolute);
    const std::string tops[] = {mountTop, deviceTop == mountTop ? std::string() : deviceTop};
    for (const std::string& top : tops) {
      if (top.empty()) {
        continue;
      }
      const std::string trash = TopDirectoryTrash(top);
      if (trash.empty()) {
        continue;
      }
      const std::string relative = absolute.substr(top == "/" ? 1 : top.size() + 1);
      const TrashMove moved = MoveIntoTrash(trash, absolute, relative);
      if (moved != TrashMove::OtherFileSystem) {
        return moved == TrashMove::Moved;
      }
    }
    return false;
  }

  /// One FO_DELETE source (a file or a folder with all it holds), as found on disk.
  [[nodiscard]] DWORD ShellDeleteOne(
    const std::string& path,
    const bool allowUndo
  )
  {
    struct stat info{};
    if (::lstat(path.c_str(), &info) != 0) {
      return ERROR_FILE_NOT_FOUND;
    }
    // A folder that is a mount point itself (another disk mounted there) is not deleted: neither
    // trash can take it by a rename, and removing it would empty that whole disk.
    if (S_ISDIR(info.st_mode)) {
      const std::size_t slash = path.find_last_of('/', path.size() > 1 ? path.size() - 2 : 0);
      const std::string parent = slash == std::string::npos ? std::string(".")
        : slash == 0                                        ? std::string("/")
                                                            : path.substr(0, slash);
      struct stat above{};
      std::string real = path;
      if (char* const resolved = ::realpath(path.c_str(), nullptr)) {
        real = resolved;
        std::free(resolved);
      }
      // Nor one with another file system mounted anywhere below it: removing or copying it would walk
      // into that one too.
      if ((::stat(parent.c_str(), &above) == 0 && above.st_dev != info.st_dev) || HoldsAMount(real)) {
        return ERROR_ACCESS_DENIED;
      }
    }
    if (allowUndo && MoveToTrash(path)) {
      return 0;
    }
    std::error_code error;
    (void)std::filesystem::remove_all(path, error);
    return error ? ErrnoToWin32(error.value()) : 0;
  }

  /**
   * SHFileOperation's FO_DELETE (engine addition, issue #255): the save, replay and profile deletes
   * (DISK_Recycle) and the cache purge (USER_PurgeAppCacheDir) on POSIX. `sources` are the
   * double-null list's paths, '/' for '\' already; each is looked up as NTFS would find it, and a
   * last component with '*' or '?' deletes every name in its folder that matches. With
   * FOF_ALLOWUNDO an entry goes to the desktop's trash instead. 0 when every source went, else the
   * first failure's code, as Windows 11 answers them: 2 for a source that isn't there, 0x7C for a
   * pattern in a folder that isn't there, and 0 for a pattern that matches nothing.
   */
  [[nodiscard]] int ShellDelete(
    const std::vector<std::string>& sources,
    const WORD flags
  )
  {
    const bool allowUndo = (flags & FOF_ALLOWUNDO) != 0;
    DWORD result = 0;
    const auto note = [&result](const DWORD error) {
      if (result == 0) {
        result = error;
      }
    };
    for (const std::string& source : sources) {
      const std::size_t slash = source.rfind('/');
      const std::string leaf = slash == std::string::npos ? source : source.substr(slash + 1);
      if (leaf.find_first_of("*?") == std::string::npos) {
        note(ShellDeleteOne(ResolveCase(source), allowUndo));
        continue;
      }
      const std::string folder = slash == std::string::npos
        ? std::string(".")
        : ResolveCase(slash == 0 ? std::string("/") : source.substr(0, slash));
      DIR* const dir = ::opendir(folder.c_str());
      if (dir == nullptr) {
        // What Windows 11 answers for a pattern in a folder that isn't there (DE_INVALIDFILES).
        note(0x7Cu);
        continue;
      }
      // Matched as _findfirst64 and FindFirstFile here match (ShellNameMatches), so a folder's listing
      // and its delete take the same names.
      std::vector<std::string> matches;
      while (const dirent* const entry = ::readdir(dir)) {
        const std::string name = entry->d_name;
        if (name != "." && name != ".." && ShellNameMatches(leaf.c_str(), name.c_str())) {
          matches.push_back(folder == "/" ? "/" + name : folder + "/" + name);
        }
      }
      (void)::closedir(dir);
      for (const std::string& match : matches) {
        note(ShellDeleteOne(match, allowUndo));
      }
    }
    return static_cast<int>(result);
  }

  /// The paths of a double-null-terminated SHFileOperation list.
  template <class Char, class Narrow>
  [[nodiscard]] std::vector<std::string> ShellSources(
    const Char* list,
    Narrow narrow
  )
  {
    std::vector<std::string> sources;
    while (list != nullptr && *list != 0) {
      sources.push_back(narrow(list));
      while (*list != 0) {
        ++list;
      }
      ++list;
    }
    return sources;
  }
} // namespace

// Engine addition (issue #255): FO_DELETE deletes as Windows' shell does (above); the other
// operations, which the engine does not use, stay unsupported and touch nothing.
int SHFileOperationA(
  SHFILEOPSTRUCTA* const operation
)
{
  if (operation == nullptr || operation->wFunc != FO_DELETE) {
    return static_cast<int>(ERROR_NOT_SUPPORTED);
  }
  operation->fAnyOperationsAborted = FALSE;
  return ShellDelete(
    ShellSources(
      operation->pFrom,
      [](const char* const path) {
    std::string out = path;
    std::replace(out.begin(), out.end(), '\\', '/');
    return out;
  }
    ),
    operation->fFlags
  );
}

int SHFileOperationW(
  SHFILEOPSTRUCTW* const operation
)
{
  if (operation == nullptr || operation->wFunc != FO_DELETE) {
    return static_cast<int>(ERROR_NOT_SUPPORTED);
  }
  operation->fAnyOperationsAborted = FALSE;
  return ShellDelete(
    ShellSources(
      operation->pFrom,
      [](const wchar_t* const path) {
    return NarrowPath(path);
  }
    ),
    operation->fFlags
  );
}

BOOL DosDateTimeToFileTime(
  const WORD fatDate,
  const WORD fatTime,
  FILETIME* const fileTime
)
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

DWORD FormatMessageA(
  const DWORD flags,
  const void*,
  const DWORD messageId,
  DWORD,
  char* const buffer,
  const DWORD size,
  va_list*
)
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

DWORD FormatMessageW(
  const DWORD flags,
  const void*,
  const DWORD messageId,
  DWORD,
  wchar_t* const buffer,
  const DWORD size,
  va_list*
)
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

char* _ctime64(
  const __time64_t* const time
) noexcept
{
  const std::time_t value = static_cast<std::time_t>(*time);
  return std::ctime(&value);
}

void _ftime64(
  __timeb64* const out
) noexcept
{
  timeval now{};
  ::gettimeofday(&now, nullptr);
  out->time = static_cast<__time64_t>(now.tv_sec);
  out->millitm = static_cast<unsigned short>(now.tv_usec / 1000);
  out->timezone = 0;
  out->dstflag = 0;
}

int fopen_s(
  std::FILE** const file,
  const char* const path,
  const char* const mode
) noexcept
{
  if (file == nullptr) {
    return EINVAL;
  }
  *file = std::fopen(SlashPath(path).c_str(), mode);
  return *file != nullptr ? 0 : errno;
}

int _wfopen_s(
  std::FILE** const file,
  const wchar_t* const path,
  const wchar_t* const mode
) noexcept
{
  return fopen_s(file, NarrowPath(path).c_str(), NarrowPath(mode).c_str());
}

int strncpy_s(
  char* const dest,
  const std::size_t destSize,
  const char* const src,
  const std::size_t count
) noexcept
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

int strcpy_s(
  char* const dest,
  const std::size_t destSize,
  const char* const src
) noexcept
{
  return strncpy_s(dest, destSize, src, src != nullptr ? std::strlen(src) : 0);
}

int vsprintf_s(
  char* const buffer,
  const std::size_t size,
  const char* const format,
  va_list arguments
) noexcept
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

int sprintf_s(
  char* const buffer,
  const std::size_t size,
  const char* const format,
  ...
) noexcept
{
  va_list arguments;
  va_start(arguments, format);
  const int written = vsprintf_s(buffer, size, format, arguments);
  va_end(arguments);
  return written;
}

int _memicmp(
  const void* const lhs,
  const void* const rhs,
  const std::size_t count
) noexcept
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

unsigned int _controlfp(
  const unsigned int newValue,
  const unsigned int mask
) noexcept
{
  // Windows x64: the rounding and exception-mask fields apply to the x87 control word and to
  // MXCSR; the precision field is not supported (ignored). Only the rounding field is mapped; the
  // engine passes _MCW_PC only, which is ignored as on x64.
#if FAFRE_ARCH_X64
  std::uint16_t x87 = 0;
  __asm__ volatile("fnstcw %0" : "=m"(x87));
  std::uint32_t mxcsr = platform::ReadMxcsr();
  if ((mask & _MCW_RC) != 0) {
    const unsigned int rc = (newValue & _MCW_RC) >> 8; // CRT 0..3 = near, down, up, chop
    x87 = static_cast<std::uint16_t>((x87 & ~0x0C00u) | (rc << 10));
    mxcsr = (mxcsr & ~0x6000u) | (rc << 13);
    __asm__ volatile("fldcw %0" ::"m"(x87));
    platform::WriteMxcsr(mxcsr);
  }
  return ((mxcsr >> 13) & 3u) << 8;
#else
  // ARM64: FPCR.RMode (bits 22-23) is 0 nearest, 1 up, 2 down, 3 toward zero; the CRT's field is
  // 0 nearest, 1 down, 2 up, 3 chop. Swapping up and down maps either way.
  constexpr unsigned int kSwapUpDown[4] = {0u, 2u, 1u, 3u};
  std::uint64_t fpcr = platform::ReadFpcr();
  if ((mask & _MCW_RC) != 0) {
    const unsigned int rc = (newValue & _MCW_RC) >> 8;
    fpcr = (fpcr & ~(3ull << 22)) | (static_cast<std::uint64_t>(kSwapUpDown[rc & 3u]) << 22);
    platform::WriteFpcr(fpcr);
  }
  return kSwapUpDown[(fpcr >> 22) & 3u] << 8;
#endif
}

// --- More of the same --------------------------------------------------------------------

namespace
{
  constexpr std::uint64_t kFileTimeUnixEpoch = 116444736000000000ull; // 1970-01-01 in FILETIME ticks

  void ToFileTime(
    const std::uint64_t ticks,
    FILETIME* const out
  ) noexcept
  {
    out->dwLowDateTime = static_cast<DWORD>(ticks & 0xFFFFFFFFu);
    out->dwHighDateTime = static_cast<DWORD>(ticks >> 32);
  }

  [[nodiscard]] std::uint64_t FromFileTime(
    const FILETIME& in
  ) noexcept
  {
    return (static_cast<std::uint64_t>(in.dwHighDateTime) << 32) | in.dwLowDateTime;
  }

  void ToSystemTime(
    const std::tm& parts,
    const unsigned milliseconds,
    SYSTEMTIME* const out
  ) noexcept
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

void GetSystemTimeAsFileTime(
  FILETIME* const fileTime
)
{
  timespec now{};
  ::clock_gettime(CLOCK_REALTIME, &now);
  ToFileTime(
    kFileTimeUnixEpoch + static_cast<std::uint64_t>(now.tv_sec) * 10000000ull +
      static_cast<std::uint64_t>(now.tv_nsec) / 100u,
    fileTime
  );
}

BOOL FileTimeToLocalFileTime(
  const FILETIME* const fileTime,
  FILETIME* const localFileTime
)
{
  const std::uint64_t ticks = FromFileTime(*fileTime);
  const std::time_t seconds = static_cast<std::time_t>((ticks - kFileTimeUnixEpoch) / 10000000ull);
  std::tm local{};
  ::localtime_r(&seconds, &local);
  ToFileTime(
    ticks + static_cast<std::uint64_t>(static_cast<std::int64_t>(local.tm_gmtoff) * 10000000ll), localFileTime
  );
  return TRUE;
}

BOOL FileTimeToSystemTime(
  const FILETIME* const fileTime,
  SYSTEMTIME* const systemTime
)
{
  const std::uint64_t ticks = FromFileTime(*fileTime);
  const std::time_t seconds = static_cast<std::time_t>((ticks - kFileTimeUnixEpoch) / 10000000ull);
  std::tm parts{};
  ::gmtime_r(&seconds, &parts);
  ToSystemTime(parts, static_cast<unsigned>((ticks / 10000u) % 1000u), systemTime);
  return TRUE;
}

void GetLocalTime(
  SYSTEMTIME* const systemTime
)
{
  timespec now{};
  ::clock_gettime(CLOCK_REALTIME, &now);
  std::tm parts{};
  ::localtime_r(&now.tv_sec, &parts);
  ToSystemTime(parts, static_cast<unsigned>(now.tv_nsec / 1000000), systemTime);
}

void GetSystemTime(
  SYSTEMTIME* const systemTime
)
{
  timespec now{};
  ::clock_gettime(CLOCK_REALTIME, &now);
  std::tm parts{};
  ::gmtime_r(&now.tv_sec, &parts);
  ToSystemTime(parts, static_cast<unsigned>(now.tv_nsec / 1000000), systemTime);
}

BOOL GetFileAttributesExA(
  const char* const path,
  const GET_FILEEX_INFO_LEVELS level,
  void* const information
)
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
    return kFileTimeUnixEpoch + static_cast<std::uint64_t>(time.tv_sec) * 10000000ull +
      static_cast<std::uint64_t>(time.tv_nsec) / 100u;
  };
  ToFileTime(toTicks(StatCreationTime(status)), &data->ftCreationTime);
  ToFileTime(toTicks(StatAccessTime(status)), &data->ftLastAccessTime);
  ToFileTime(toTicks(StatWriteTime(status)), &data->ftLastWriteTime);
  const std::uint64_t size = static_cast<std::uint64_t>(status.st_size);
  data->nFileSizeHigh = static_cast<DWORD>(size >> 32);
  data->nFileSizeLow = static_cast<DWORD>(size & 0xFFFFFFFFu);
  return TRUE;
}

BOOL GetFileAttributesExW(
  const wchar_t* const path,
  const GET_FILEEX_INFO_LEVELS level,
  void* const information
)
{
  return GetFileAttributesExA(NarrowPath(path).c_str(), level, information);
}

namespace
{
  // One FindFirstFileA search: the folder and the wildcard its entries are matched against.
  struct Win32FindSearch
  {
    DIR* directory = nullptr;
    std::string folder;  // with a trailing '/'
    std::string pattern; // the last component of the request, '*' and '?' wildcards
  };

  // The next entry of `search` that matches its pattern, case-insensitively as on Windows.
  [[nodiscard]] bool NextMatch(
    Win32FindSearch& search,
    WIN32_FIND_DATAA* const found
  )
  {
    while (dirent* const entry = ::readdir(search.directory)) {
      if (!ShellNameMatches(search.pattern.c_str(), entry->d_name)) {
        continue;
      }
      WIN32_FILE_ATTRIBUTE_DATA attributes{};
      if (!GetFileAttributesExA((search.folder + entry->d_name).c_str(), GetFileExInfoStandard, &attributes)) {
        continue; // gone since the listing
      }
      *found = WIN32_FIND_DATAA{};
      found->dwFileAttributes = attributes.dwFileAttributes;
      found->ftCreationTime = attributes.ftCreationTime;
      found->ftLastAccessTime = attributes.ftLastAccessTime;
      found->ftLastWriteTime = attributes.ftLastWriteTime;
      found->nFileSizeHigh = attributes.nFileSizeHigh;
      found->nFileSizeLow = attributes.nFileSizeLow;
      std::snprintf(found->cFileName, sizeof(found->cFileName), "%s", entry->d_name);
      return true;
    }
    return false;
  }
} // namespace

HANDLE FindFirstFileA(
  const char* const fileName,
  WIN32_FIND_DATAA* const found
)
{
  if (fileName == nullptr || found == nullptr) {
    tLastError = ERROR_INVALID_PARAMETER;
    return INVALID_HANDLE_VALUE;
  }
  std::string request(fileName);
  std::replace(request.begin(), request.end(), '\\', '/');
  const std::size_t slash = request.find_last_of('/');
  auto search = std::make_unique<Win32FindSearch>();
  // Only the folder part is a path to resolve; the last part is the wildcard.
  search->folder = (slash == std::string::npos) ? std::string(".") : SlashPath(request.substr(0, slash).c_str());
  search->pattern = (slash == std::string::npos) ? request : request.substr(slash + 1);
  search->directory = ::opendir(search->folder.c_str());
  if (search->directory == nullptr) {
    SetErrnoError();
    return INVALID_HANDLE_VALUE;
  }
  search->folder += '/';
  if (!NextMatch(*search, found)) {
    ::closedir(search->directory);
    tLastError = ERROR_FILE_NOT_FOUND;
    return INVALID_HANDLE_VALUE;
  }
  return search.release();
}

BOOL FindNextFileA(
  const HANDLE handle,
  WIN32_FIND_DATAA* const found
)
{
  if (handle == nullptr || handle == INVALID_HANDLE_VALUE || found == nullptr) {
    tLastError = ERROR_INVALID_HANDLE;
    return FALSE;
  }
  if (!NextMatch(*static_cast<Win32FindSearch*>(handle), found)) {
    tLastError = ERROR_NO_MORE_FILES;
    return FALSE;
  }
  return TRUE;
}

namespace
{
  void WidenFound(
    const WIN32_FIND_DATAA& narrow,
    WIN32_FIND_DATAW* const wide
  )
  {
    *wide = WIN32_FIND_DATAW{};
    wide->dwFileAttributes = narrow.dwFileAttributes;
    wide->ftCreationTime = narrow.ftCreationTime;
    wide->ftLastAccessTime = narrow.ftLastAccessTime;
    wide->ftLastWriteTime = narrow.ftLastWriteTime;
    wide->nFileSizeHigh = narrow.nFileSizeHigh;
    wide->nFileSizeLow = narrow.nFileSizeLow;
    const std::wstring name = WidenUtf8(narrow.cFileName);
    const std::size_t count = (std::min)(name.size(), static_cast<std::size_t>(MAX_PATH - 1));
    std::copy_n(name.c_str(), count, wide->cFileName);
    wide->cFileName[count] = L'\0';
  }
} // namespace

HANDLE FindFirstFileW(
  const wchar_t* const fileName,
  WIN32_FIND_DATAW* const found
)
{
  if (fileName == nullptr || found == nullptr) {
    tLastError = ERROR_INVALID_PARAMETER;
    return INVALID_HANDLE_VALUE;
  }
  WIN32_FIND_DATAA narrow{};
  const HANDLE search = FindFirstFileA(NarrowPath(fileName).c_str(), &narrow);
  if (search != INVALID_HANDLE_VALUE) {
    WidenFound(narrow, found);
  }
  return search;
}

BOOL FindNextFileW(
  const HANDLE search,
  WIN32_FIND_DATAW* const found
)
{
  if (found == nullptr) {
    tLastError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  WIN32_FIND_DATAA narrow{};
  if (!FindNextFileA(search, &narrow)) {
    return FALSE;
  }
  WidenFound(narrow, found);
  return TRUE;
}

BOOL FindClose(
  const HANDLE handle
)
{
  if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
    return FALSE;
  }
  auto* const search = static_cast<Win32FindSearch*>(handle);
  ::closedir(search->directory);
  delete search;
  return TRUE;
}

void GetCurrentProcessorNumberEx(
  PROCESSOR_NUMBER* const number
)
{
  number->Group = 0;
  number->Number = static_cast<BYTE>(platform::posix::CurrentProcessorNumber());
  number->Reserved = 0;
}

BOOL SetThreadGroupAffinity(
  const HANDLE thread,
  const GROUP_AFFINITY* const affinity,
  GROUP_AFFINITY* const previous
)
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

BOOL SetThreadIdealProcessorEx(
  const HANDLE thread,
  PROCESSOR_NUMBER* const ideal,
  PROCESSOR_NUMBER* const previous
)
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

BOOL GetNumaProcessorNode(
  UCHAR,
  UCHAR* const nodeNumber
)
{
  if (nodeNumber != nullptr) {
    *nodeNumber = 0;
  }
  return TRUE;
}

BOOL GetNumaNodeProcessorMask(
  const UCHAR node,
  ULONGLONG* const processorMask
)
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

int _vsnprintf(
  char* const buffer,
  const std::size_t count,
  const char* const format,
  va_list arguments
) noexcept
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
int _vsnwprintf(
  wchar_t* const buffer,
  const std::size_t count,
  const wchar_t* const format,
  va_list arguments
) noexcept
{
  const int written = std::vswprintf(buffer, count, format, arguments);
  return written < 0 ? -1 : written;
}

int _snprintf(
  char* const buffer,
  const std::size_t count,
  const char* const format,
  ...
) noexcept
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

  [[nodiscard]] __time64_t ToTime64(
    const struct timespec& time
  ) noexcept
  {
    return static_cast<__time64_t>(time.tv_sec);
  }
} // namespace

std::intptr_t _findfirst64(
  const char* const spec,
  __finddata64_t* const data
)
{
  if (spec == nullptr || data == nullptr) {
    errno = EINVAL;
    return -1;
  }
  const std::string path = SlashPath(spec);
  const std::size_t slash = path.find_last_of('/');
  const std::string directory = slash == std::string::npos ? std::string(".")
    : slash == 0                                           ? std::string("/")
                                                           : path.substr(0, slash);
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
    if (!ShellNameMatches(pattern.c_str(), entry->d_name)) {
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
      match.time_create = ToTime64(StatCreationTime(status));
      match.time_access = ToTime64(StatAccessTime(status));
      match.time_write = ToTime64(StatWriteTime(status));
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

int _findnext64(
  const std::intptr_t handle,
  __finddata64_t* const data
)
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

int _findclose(
  const std::intptr_t handle
)
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
  __attribute__((constructor(101))) void CaptureCommandLine(
    const int argc,
    char** const argv,
    char**
  )
  {
    __argc = argc;
    __argv = argv;
  }
} // namespace

#endif // !FAFRE_PLATFORM_WINDOWS
