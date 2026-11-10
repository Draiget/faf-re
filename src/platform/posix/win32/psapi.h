#pragma once

// Engine addition (issue #255): <psapi.h> for the Linux client: the process memory counters the
// render statistics show, read from /proc/self/status (VmRSS is the working set, VmHWM its peak,
// VmData the private bytes). Fields have the Windows names and order.

#if FAFRE_PLATFORM_WINDOWS
#error "platform/posix/win32/psapi.h is for builds without the Windows SDK"
#endif

#include <cstddef>
#include <cstdio>
#include <cstring>

#include <Windows.h>

struct PROCESS_MEMORY_COUNTERS
{
  DWORD cb;
  DWORD PageFaultCount;
  std::size_t PeakWorkingSetSize;
  std::size_t WorkingSetSize;
  std::size_t QuotaPeakPagedPoolUsage;
  std::size_t QuotaPagedPoolUsage;
  std::size_t QuotaPeakNonPagedPoolUsage;
  std::size_t QuotaNonPagedPoolUsage;
  std::size_t PagefileUsage;
  std::size_t PeakPagefileUsage;
};

struct PROCESS_MEMORY_COUNTERS_EX
{
  DWORD cb;
  DWORD PageFaultCount;
  std::size_t PeakWorkingSetSize;
  std::size_t WorkingSetSize;
  std::size_t QuotaPeakPagedPoolUsage;
  std::size_t QuotaPagedPoolUsage;
  std::size_t QuotaPeakNonPagedPoolUsage;
  std::size_t QuotaNonPagedPoolUsage;
  std::size_t PagefileUsage;
  std::size_t PeakPagefileUsage;
  std::size_t PrivateUsage;
};

// The calling process only (`process` is GetCurrentProcess()); `size` picks the structure.
inline BOOL GetProcessMemoryInfo(HANDLE process, PROCESS_MEMORY_COUNTERS* const counters, const DWORD size)
{
  (void)process;
  if (counters == nullptr || size < sizeof(PROCESS_MEMORY_COUNTERS)) {
    return FALSE;
  }
  std::memset(counters, 0, size);
  counters->cb = size;
  std::FILE* const status = std::fopen("/proc/self/status", "r");
  if (status == nullptr) {
    return FALSE;
  }
  char line[256];
  std::size_t privateBytes = 0;
  while (std::fgets(line, sizeof(line), status) != nullptr) {
    unsigned long long kilobytes = 0;
    if (std::sscanf(line, "VmRSS: %llu kB", &kilobytes) == 1) {
      counters->WorkingSetSize = static_cast<std::size_t>(kilobytes) * 1024u;
    } else if (std::sscanf(line, "VmHWM: %llu kB", &kilobytes) == 1) {
      counters->PeakWorkingSetSize = static_cast<std::size_t>(kilobytes) * 1024u;
    } else if (std::sscanf(line, "VmData: %llu kB", &kilobytes) == 1) {
      privateBytes = static_cast<std::size_t>(kilobytes) * 1024u;
    }
  }
  std::fclose(status);
  counters->PagefileUsage = privateBytes;
  counters->PeakPagefileUsage = privateBytes;
  if (size >= sizeof(PROCESS_MEMORY_COUNTERS_EX)) {
    reinterpret_cast<PROCESS_MEMORY_COUNTERS_EX*>(counters)->PrivateUsage = privateBytes;
  }
  return TRUE;
}
