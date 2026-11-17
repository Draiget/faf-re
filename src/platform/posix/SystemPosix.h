#pragma once

#include "../PlatformDefines.h"

// Engine addition (macOS milestone, #269): the operating-system services the POSIX Win32 shim
// (platform/posix/Win32Shim.cpp) and the diagnostics need, with one body per system in
// platform/posix/SystemPosix.cpp: Linux reads /proc, macOS asks Mach and the BSD calls.

#if FAFRE_PLATFORM_POSIX

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace platform::posix
{
  /// The calling thread's system-wide id (Linux's tid; macOS's 64-bit thread id, low half).
  [[nodiscard]] std::uint32_t CurrentThreadId() noexcept;

  /// Whether a thread of this process has the id CurrentThreadId() gave it.
  [[nodiscard]] bool ThreadExists(std::uint32_t threadId) noexcept;

  /// The process's arguments as /proc/self/cmdline holds them, each ended by '\0', into `out`;
  /// the bytes written. Uses no heap: the allocator asks for the command line while it starts.
  [[nodiscard]] std::size_t ReadArguments(char* out, std::size_t capacity) noexcept;

  /// The usable size of a malloc block.
  [[nodiscard]] std::size_t AllocationSize(const void* block) noexcept;

  /// The CPUs the process may run on, one bit per CPU (the first 64).
  [[nodiscard]] std::uint64_t ProcessCpuMask() noexcept;

  /// Every online CPU (the first 64).
  [[nodiscard]] std::uint64_t OnlineCpuMask() noexcept;

  /// Restricts the process to `mask`; false when the system refused.
  [[nodiscard]] bool SetProcessCpuMask(std::uint64_t mask) noexcept;

  /**
   * Restricts the calling thread to `mask` and returns its previous mask (0 when refused).
   * macOS has no CPU affinity: the mask is recorded and reported back, and a thread the engine pins
   * (a simulation or render thread) gets the user-interactive QoS class instead, which keeps it on
   * the performance cores.
   */
  [[nodiscard]] std::uint64_t SetThreadCpuMask(std::uint64_t mask) noexcept;

  /// The logical CPUs of each physical core (SMT siblings share one), in CPU order.
  [[nodiscard]] std::vector<std::uint64_t> CoreCpuMasks();

  /// The logical CPUs of each NUMA node, indexed by node number; 0 for a number with no node (the
  /// numbers can have gaps). One node where the system has no NUMA.
  [[nodiscard]] std::vector<std::uint64_t> NumaNodeCpuMasks();

  /// The CPU the calling thread runs on, or 0 where the system doesn't say (macOS).
  [[nodiscard]] unsigned CurrentProcessorNumber() noexcept;

  struct MemoryRegion
  {
    std::uintptr_t begin = 0;
    std::uintptr_t end = 0;
    bool readable = false;
    bool writable = false;
    bool isPrivate = false;
  };

  /// The mapped region holding `address`; empty when nothing is mapped there.
  [[nodiscard]] std::optional<MemoryRegion> FindMemoryRegion(std::uintptr_t address) noexcept;

  /// Where the executable's image starts in memory (GetModuleHandle(nullptr)).
  [[nodiscard]] void* ExecutableImageBase() noexcept;

  /// The absolute path of the running executable, empty when unknown.
  [[nodiscard]] std::string ExecutablePath();

  /// The file system mount points, bind mounts included (Linux); empty when the system won't say.
  [[nodiscard]] std::vector<std::string> MountPoints();

  /// The process's environment, as `environ` (which macOS doesn't declare for executables) holds it,
  /// for posix_spawn.
  [[nodiscard]] char** Environment() noexcept;

  /**
   * Ends this process, without cleanup, once the process `parent` has exited, and at once when it
   * already has or is not this process's parent. For a helper the game starts and doesn't wait for
   * (the replay viewer's keyframe preparer, moho/sim/ReplayTimeline.cpp), so it can't outlive the
   * game. Linux arms PR_SET_PDEATHSIG; macOS, which has no such call, watches the parent with kqueue
   * on a thread of its own.
   */
  void ExitWithParent(int parent) noexcept;
} // namespace platform::posix

#endif
