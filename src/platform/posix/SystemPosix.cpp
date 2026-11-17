// Engine addition (macOS milestone, #269): platform/posix/SystemPosix.h on Linux and on macOS.

#include "platform/posix/SystemPosix.h"

#if FAFRE_PLATFORM_POSIX

#include <algorithm>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>

#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#if FAFRE_PLATFORM_LINUX // /proc, malloc_usable_size, sched_*affinity, gettid, prctl
#include <malloc.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

extern "C" char __executable_start; // the GNU linkers' symbol for the image's first byte
#elif FAFRE_PLATFORM_MACOS          // Mach, the dyld and malloc zone APIs, getmntinfo, kqueue
#include <crt_externs.h>
#include <sys/event.h>
#include <mach-o/dyld.h>
#include <mach-o/ldsyms.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <malloc/malloc.h>
#include <pthread/qos.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#endif

namespace platform::posix
{
#if FAFRE_PLATFORM_LINUX // the /proc file system and the Linux scheduler calls
  namespace
  {
    /// A CPU list file ("0-3,8-11") as a mask.
    [[nodiscard]] std::uint64_t ReadCpuListFile(
      const char* const path
    )
    {
      std::ifstream file(path);
      std::string list;
      if (!file || !std::getline(file, list)) {
        return 0;
      }
      std::uint64_t mask = 0;
      const char* cursor = list.c_str();
      while (*cursor != '\0') {
        char* end = nullptr;
        const unsigned long first = std::strtoul(cursor, &end, 10);
        if (end == cursor) {
          break;
        }
        unsigned long last = first;
        cursor = end;
        if (*cursor == '-') {
          last = std::strtoul(cursor + 1, &end, 10);
          cursor = end;
        }
        for (unsigned long cpu = first; cpu <= last && cpu < 64; ++cpu) {
          mask |= 1ull << cpu;
        }
        if (*cursor != ',') {
          break;
        }
        ++cursor;
      }
      return mask;
    }

    [[nodiscard]] std::uint64_t MaskOf(
      const cpu_set_t& set
    ) noexcept
    {
      std::uint64_t mask = 0;
      for (unsigned cpu = 0; cpu < 64; ++cpu) {
        if (CPU_ISSET(cpu, &set)) {
          mask |= 1ull << cpu;
        }
      }
      return mask;
    }

    [[nodiscard]] cpu_set_t SetOf(
      const std::uint64_t mask
    ) noexcept
    {
      cpu_set_t set;
      CPU_ZERO(&set);
      for (unsigned cpu = 0; cpu < 64; ++cpu) {
        if ((mask & (1ull << cpu)) != 0) {
          CPU_SET(cpu, &set);
        }
      }
      return set;
    }

    /// The process's CPU set. Linux keeps a set per thread, so a pinned thread must not change what
    /// this reports: it is read before main starts, and only SetProcessCpuMask changes it.
    [[nodiscard]] std::uint64_t& ProcessMask() noexcept
    {
      static std::uint64_t mask = [] {
        cpu_set_t initial;
        CPU_ZERO(&initial);
        (void)::sched_getaffinity(0, sizeof(initial), &initial);
        return MaskOf(initial);
      }();
      return mask;
    }
    [[maybe_unused]] const bool sProcessMaskRead = (static_cast<void>(ProcessMask()), true);
  } // namespace

  std::uint32_t CurrentThreadId() noexcept
  {
    return static_cast<std::uint32_t>(::syscall(SYS_gettid));
  }

  bool ThreadExists(
    const std::uint32_t threadId
  ) noexcept
  {
    char taskPath[64]{};
    std::snprintf(taskPath, sizeof(taskPath), "/proc/self/task/%u", static_cast<unsigned>(threadId));
    return ::access(taskPath, F_OK) == 0;
  }

  std::size_t ReadArguments(
    char* const out,
    const std::size_t capacity
  ) noexcept
  {
    const int fd = ::open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      return 0;
    }
    const ssize_t got = ::read(fd, out, capacity);
    (void)::close(fd);
    return got > 0 ? static_cast<std::size_t>(got) : 0;
  }

  std::size_t AllocationSize(
    const void* const block
  ) noexcept
  {
    return ::malloc_usable_size(const_cast<void*>(block));
  }

  std::uint64_t ProcessCpuMask() noexcept
  {
    return ProcessMask();
  }

  std::uint64_t OnlineCpuMask() noexcept
  {
    // Every online CPU, as Windows reports it, so a process given fewer can tell. A process cannot run outside
    // its set, so that set is what remains when the file can't be read.
    return ReadCpuListFile("/sys/devices/system/cpu/online") | ProcessMask();
  }

  bool SetProcessCpuMask(
    const std::uint64_t mask
  ) noexcept
  {
    const cpu_set_t wanted = SetOf(mask);
    if (::sched_setaffinity(0, sizeof(wanted), &wanted) != 0) {
      return false;
    }
    // What the kernel kept: a CPU outside the container's set drops out.
    cpu_set_t kept;
    CPU_ZERO(&kept);
    (void)::sched_getaffinity(0, sizeof(kept), &kept);
    ProcessMask() = MaskOf(kept);
    return true;
  }

  std::uint64_t SetThreadCpuMask(
    const std::uint64_t mask
  ) noexcept
  {
    cpu_set_t previous;
    CPU_ZERO(&previous);
    (void)::pthread_getaffinity_np(::pthread_self(), sizeof(previous), &previous);
    const cpu_set_t wanted = SetOf(mask);
    if (::pthread_setaffinity_np(::pthread_self(), sizeof(wanted), &wanted) != 0) {
      return 0;
    }
    const std::uint64_t previousMask = MaskOf(previous);
    return previousMask != 0 ? previousMask : 1u;
  }

  std::vector<std::uint64_t> CoreCpuMasks()
  {
    std::vector<std::uint64_t> cores;
    const std::uint64_t online = ReadCpuListFile("/sys/devices/system/cpu/online");
    std::uint64_t seen = 0;
    for (unsigned cpu = 0; cpu < 64; ++cpu) {
      const std::uint64_t bit = 1ull << cpu;
      if ((online & bit) == 0 || (seen & bit) != 0) {
        continue;
      }
      const std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/thread_siblings_list";
      const std::uint64_t siblings = ReadCpuListFile(path.c_str());
      const std::uint64_t core = (siblings != 0 ? siblings : bit) & online;
      seen |= core;
      cores.push_back(core);
    }
    return cores;
  }

  std::vector<std::uint64_t> NumaNodeCpuMasks()
  {
    std::vector<std::uint64_t> nodes(64);
    for (unsigned node = 0; node < 64; ++node) {
      const std::string path = "/sys/devices/system/node/node" + std::to_string(node) + "/cpulist";
      nodes[node] = ReadCpuListFile(path.c_str());
    }
    return nodes;
  }

  unsigned CurrentProcessorNumber() noexcept
  {
    const int cpu = ::sched_getcpu();
    return cpu >= 0 ? static_cast<unsigned>(cpu) : 0u;
  }

  std::optional<MemoryRegion> FindMemoryRegion(
    const std::uintptr_t address
  ) noexcept
  {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
      unsigned long begin = 0;
      unsigned long end = 0;
      char permissions[5] = {};
      if (std::sscanf(line.c_str(), "%lx-%lx %4s", &begin, &end, permissions) != 3) {
        continue;
      }
      if (address < begin || address >= end) {
        continue;
      }
      return MemoryRegion{
        .begin = begin,
        .end = end,
        .readable = permissions[0] == 'r',
        .writable = permissions[1] == 'w',
        .isPrivate = permissions[3] == 'p',
      };
    }
    return std::nullopt;
  }

  void* ExecutableImageBase() noexcept
  {
    return &__executable_start;
  }

  std::string ExecutablePath()
  {
    char exe[4096]{};
    const ssize_t length = ::readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    return length > 0 ? std::string(exe, static_cast<std::size_t>(length)) : std::string();
  }

  std::vector<std::string> MountPoints()
  {
    std::vector<std::string> points;
    std::ifstream table("/proc/self/mountinfo");
    for (std::string line; std::getline(table, line);) {
      // "<id> <parent> <major:minor> <root> <mount point> ...", spaces in it as \040.
      std::size_t at = 0;
      for (int field = 0; field < 4 && at != std::string::npos; ++field) {
        at = line.find(' ', at);
        if (at != std::string::npos) {
          ++at;
        }
      }
      if (at == std::string::npos) {
        continue;
      }
      const std::size_t end = line.find(' ', at);
      const std::string escaped = line.substr(at, end == std::string::npos ? std::string::npos : end - at);
      std::string point;
      for (std::size_t k = 0; k < escaped.size(); ++k) {
        if (
          escaped[k] == '\\' && k + 3 < escaped.size() && escaped[k + 1] >= '0' && escaped[k + 1] <= '3' &&
          escaped[k + 2] >= '0' && escaped[k + 2] <= '7' && escaped[k + 3] >= '0' && escaped[k + 3] <= '7'
        ) {
          point.push_back(
            static_cast<char>((escaped[k + 1] - '0') * 64 + (escaped[k + 2] - '0') * 8 + (escaped[k + 3] - '0'))
          );
          k += 3;
        } else {
          point.push_back(escaped[k]);
        }
      }
      points.push_back(std::move(point));
    }
    return points;
  }

  char** Environment() noexcept
  {
    return environ;
  }

  void ExitWithParent(
    const int parent
  ) noexcept
  {
    (void)::prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (::getppid() != parent) {
      ::_exit(0); // the parent ended before the signal was armed
    }
  }
#elif FAFRE_PLATFORM_MACOS // Mach threads and VM regions, dyld, the malloc zone, BSD mount table
  namespace
  {
    /// A mask of the first `count` CPUs.
    [[nodiscard]] constexpr std::uint64_t FirstCpus(
      const unsigned count
    ) noexcept
    {
      return count >= 64 ? ~0ull : (1ull << count) - 1;
    }

    /// The number of logical CPUs.
    [[nodiscard]] unsigned LogicalCpus() noexcept
    {
      int count = 0;
      std::size_t size = sizeof(count);
      if (::sysctlbyname("hw.logicalcpu", &count, &size, nullptr, 0) != 0 || count <= 0) {
        return 1;
      }
      return static_cast<unsigned>(count);
    }

    /// What SetProcessCpuMask and SetThreadCpuMask were last given (macOS has no affinity to apply).
    std::uint64_t sProcessMask = 0;
    thread_local std::uint64_t tThreadMask = 0;
  } // namespace

  std::uint32_t CurrentThreadId() noexcept
  {
    std::uint64_t id = 0;
    (void)::pthread_threadid_np(nullptr, &id);
    return static_cast<std::uint32_t>(id);
  }

  bool ThreadExists(
    const std::uint32_t threadId
  ) noexcept
  {
    thread_act_array_t threads = nullptr;
    mach_msg_type_number_t count = 0;
    if (::task_threads(::mach_task_self(), &threads, &count) != KERN_SUCCESS) {
      return false;
    }
    bool found = false;
    for (mach_msg_type_number_t i = 0; i < count; ++i) {
      thread_identifier_info_data_t info{};
      mach_msg_type_number_t infoCount = THREAD_IDENTIFIER_INFO_COUNT;
      if (
        !found &&
        ::thread_info(threads[i], THREAD_IDENTIFIER_INFO, reinterpret_cast<thread_info_t>(&info), &infoCount) ==
          KERN_SUCCESS &&
        static_cast<std::uint32_t>(info.thread_id) == threadId
      ) {
        found = true;
      }
      (void)::mach_port_deallocate(::mach_task_self(), threads[i]);
    }
    (void)::vm_deallocate(::mach_task_self(), reinterpret_cast<vm_address_t>(threads), count * sizeof(thread_act_t));
    return found;
  }

  std::size_t ReadArguments(
    char* const out,
    const std::size_t capacity
  ) noexcept
  {
    const int argc = *::_NSGetArgc();
    char** const argv = *::_NSGetArgv();
    std::size_t written = 0;
    for (int i = 0; i < argc && argv[i] != nullptr; ++i) {
      const std::size_t length = std::strlen(argv[i]) + 1;
      if (written + length > capacity) {
        break;
      }
      std::memcpy(out + written, argv[i], length);
      written += length;
    }
    return written;
  }

  std::size_t AllocationSize(
    const void* const block
  ) noexcept
  {
    return ::malloc_size(block);
  }

  std::uint64_t ProcessCpuMask() noexcept
  {
    return sProcessMask != 0 ? sProcessMask : FirstCpus(LogicalCpus());
  }

  std::uint64_t OnlineCpuMask() noexcept
  {
    return FirstCpus(LogicalCpus());
  }

  bool SetProcessCpuMask(
    const std::uint64_t mask
  ) noexcept
  {
    sProcessMask = mask & OnlineCpuMask();
    return sProcessMask != 0;
  }

  std::uint64_t SetThreadCpuMask(
    const std::uint64_t mask
  ) noexcept
  {
    const std::uint64_t previous = tThreadMask != 0 ? tThreadMask : ProcessCpuMask();
    tThreadMask = mask;
    (void)::pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    return previous;
  }

  std::vector<std::uint64_t> CoreCpuMasks()
  {
    // Apple silicon has no SMT: every logical CPU is a core of its own.
    std::vector<std::uint64_t> cores;
    for (unsigned cpu = 0; cpu < std::min(LogicalCpus(), 64u); ++cpu) {
      cores.push_back(1ull << cpu);
    }
    return cores;
  }

  std::vector<std::uint64_t> NumaNodeCpuMasks()
  {
    return {OnlineCpuMask()};
  }

  unsigned CurrentProcessorNumber() noexcept
  {
    return 0;
  }

  std::optional<MemoryRegion> FindMemoryRegion(
    const std::uintptr_t address
  ) noexcept
  {
    mach_vm_address_t begin = address;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info{};
    mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    const kern_return_t result = ::mach_vm_region(
      ::mach_task_self(),
      &begin,
      &size,
      VM_REGION_BASIC_INFO_64,
      reinterpret_cast<vm_region_info_t>(&info),
      &infoCount,
      &object
    );
    if (result != KERN_SUCCESS || begin > address) {
      return std::nullopt; // the next region starts above `address`: nothing is mapped there
    }
    return MemoryRegion{
      .begin = static_cast<std::uintptr_t>(begin),
      .end = static_cast<std::uintptr_t>(begin + size),
      .readable = (info.protection & VM_PROT_READ) != 0,
      .writable = (info.protection & VM_PROT_WRITE) != 0,
      .isPrivate = info.shared == 0,
    };
  }

  void* ExecutableImageBase() noexcept
  {
    return const_cast<mach_header_64*>(&_mh_execute_header);
  }

  std::string ExecutablePath()
  {
    std::uint32_t size = 0;
    (void)::_NSGetExecutablePath(nullptr, &size);
    std::string path(size, '\0');
    if (::_NSGetExecutablePath(path.data(), &size) != 0) {
      return {};
    }
    char resolved[PATH_MAX]{};
    if (::realpath(path.c_str(), resolved) == nullptr) {
      return path.c_str();
    }
    return resolved;
  }

  std::vector<std::string> MountPoints()
  {
    std::vector<std::string> points;
    struct statfs* mounts = nullptr;
    const int count = ::getmntinfo(&mounts, MNT_NOWAIT);
    for (int i = 0; i < count; ++i) {
      points.emplace_back(mounts[i].f_mntonname);
    }
    return points;
  }

  char** Environment() noexcept
  {
    return *::_NSGetEnviron();
  }

  void ExitWithParent(
    const int parent
  ) noexcept
  {
    const int queue = ::kqueue();
    struct kevent watch{};
    EV_SET(&watch, static_cast<uintptr_t>(parent), EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, nullptr);
    // ESRCH: the parent is gone already. Checked after arming, so an exit between the two isn't missed.
    if (queue < 0 || ::kevent(queue, &watch, 1, nullptr, 0, nullptr) != 0 || ::getppid() != parent) {
      ::_exit(0);
    }
    pthread_t watcher{};
    if (::pthread_create(&watcher, nullptr, [](void* const context) -> void* {
      struct kevent fired{};
      while (::kevent(static_cast<int>(reinterpret_cast<std::intptr_t>(context)), nullptr, 0, &fired, 1, nullptr) < 0) {
      }
      ::_exit(0);
    }, reinterpret_cast<void*>(static_cast<std::intptr_t>(queue))) == 0) {
      (void)::pthread_detach(watcher);
    }
  }
#endif
} // namespace platform::posix

#endif // FAFRE_PLATFORM_POSIX
