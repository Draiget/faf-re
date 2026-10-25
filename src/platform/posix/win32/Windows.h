#pragma once

// Engine addition (dedicated-server plan WPL.5): the subset of <Windows.h> the shared
// simulation code uses, for the Linux build (cmake/FafLinux.cmake puts this directory on
// the include path; Windows builds never see it). Types and constants have their Windows
// sizes and values; the functions are implemented on POSIX in
// src/platform/posix/Win32Shim.cpp with the Windows semantics the engine relies on
// (manual/auto-reset events, waits with timeouts, interlocked operations on 32-bit values,
// the performance counter, the calling thread's id).

#if defined(_WIN32)
#error "platform/posix/win32/Windows.h is for builds without the Windows SDK"
#endif

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>

#define WINAPI
#define CALLBACK
#define APIENTRY
#define WINBASEAPI

using BOOL = int;
using BYTE = std::uint8_t;
using UCHAR = unsigned char;
using CHAR = char;
using WCHAR = wchar_t;
using WORD = std::uint16_t;
using DWORD = std::uint32_t;
using UINT = unsigned int;
using INT = int;
using LONG = std::int32_t;
using ULONG = std::uint32_t;
using DWORD_PTR = std::uintptr_t;
using ULONG_PTR = std::uintptr_t;
using UINT_PTR = std::uintptr_t;
using INT_PTR = std::intptr_t;
using LONG_PTR = std::intptr_t;
using SIZE_T = std::size_t;
using HANDLE = void*;
using HMODULE = void*;
using HINSTANCE = void*;
using HWND = void*;
using HDC = void*;
using LPVOID = void*;
using LPCVOID = const void*;
using LPSTR = char*;
using LPCSTR = const char*;
using LPWSTR = wchar_t*;
using LPCWSTR = const wchar_t*;
using DWORD64 = std::uint64_t;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define INFINITE 0xFFFFFFFFu
#define WAIT_OBJECT_0 0x00000000u
#define WAIT_ABANDONED 0x00000080u
#define WAIT_TIMEOUT 0x00000102u
#define WAIT_FAILED 0xFFFFFFFFu
#define INVALID_HANDLE_VALUE (reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-1)))
#define MAX_PATH 260

struct FILETIME
{
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
};

union LARGE_INTEGER
{
  struct
  {
    DWORD LowPart;
    LONG HighPart;
  };
  std::int64_t QuadPart;
};

struct RECT
{
  LONG left;
  LONG top;
  LONG right;
  LONG bottom;
};

struct POINT
{
  LONG x;
  LONG y;
};

struct SYSTEM_INFO
{
  WORD wProcessorArchitecture;
  WORD wReserved;
  DWORD dwPageSize;
  LPVOID lpMinimumApplicationAddress;
  LPVOID lpMaximumApplicationAddress;
  DWORD_PTR dwActiveProcessorMask;
  DWORD dwNumberOfProcessors;
  DWORD dwProcessorType;
  DWORD dwAllocationGranularity;
  WORD wProcessorLevel;
  WORD wProcessorRevision;
};

// --- Synchronisation (Win32Shim.cpp) ----------------------------------------------------
HANDLE CreateEventW(void* attributes, BOOL manualReset, BOOL initialState, const wchar_t* name);
HANDLE CreateEventA(void* attributes, BOOL manualReset, BOOL initialState, const char* name);
#define CreateEvent CreateEventW
HANDLE CreateSemaphoreW(void* attributes, LONG initialCount, LONG maximumCount, const wchar_t* name);
BOOL ReleaseSemaphore(HANDLE semaphore, LONG releaseCount, LONG* previousCount);
BOOL SetEvent(HANDLE event);
BOOL ResetEvent(HANDLE event);
DWORD WaitForSingleObject(HANDLE handle, DWORD milliseconds);
DWORD WaitForSingleObjectEx(HANDLE handle, DWORD milliseconds, BOOL alertable);
DWORD WaitForMultipleObjects(DWORD count, const HANDLE* handles, BOOL waitAll, DWORD milliseconds);
BOOL CloseHandle(HANDLE handle);

// --- Threads and time --------------------------------------------------------------------
DWORD GetCurrentThreadId();
HANDLE GetCurrentThread();
HANDLE GetCurrentProcess();
DWORD GetCurrentProcessId();
void Sleep(DWORD milliseconds);
DWORD SleepEx(DWORD milliseconds, BOOL alertable);
DWORD GetTickCount();
BOOL QueryPerformanceCounter(LARGE_INTEGER* count);
BOOL QueryPerformanceFrequency(LARGE_INTEGER* frequency);
void GetSystemInfo(SYSTEM_INFO* info);
DWORD GetLastError();
void SetLastError(DWORD error);

#define THREAD_PRIORITY_LOWEST (-2)
#define THREAD_PRIORITY_BELOW_NORMAL (-1)
#define THREAD_PRIORITY_NORMAL 0
#define THREAD_PRIORITY_ABOVE_NORMAL 1
#define THREAD_PRIORITY_HIGHEST 2
#define THREAD_PRIORITY_TIME_CRITICAL 15
#define THREAD_PRIORITY_IDLE (-15)
BOOL SetThreadPriority(HANDLE thread, int priority);
DWORD_PTR SetThreadAffinityMask(HANDLE thread, DWORD_PTR mask);

// --- Interlocked operations on 32- and 64-bit values -------------------------------------
inline LONG InterlockedIncrement(volatile LONG* value) noexcept
{
  return __atomic_add_fetch(value, 1, __ATOMIC_SEQ_CST);
}
inline LONG InterlockedDecrement(volatile LONG* value) noexcept
{
  return __atomic_sub_fetch(value, 1, __ATOMIC_SEQ_CST);
}
inline LONG InterlockedExchange(volatile LONG* target, const LONG value) noexcept
{
  return __atomic_exchange_n(target, value, __ATOMIC_SEQ_CST);
}
inline LONG InterlockedExchangeAdd(volatile LONG* target, const LONG value) noexcept
{
  return __atomic_fetch_add(target, value, __ATOMIC_SEQ_CST);
}
inline LONG InterlockedCompareExchange(volatile LONG* target, const LONG exchange, LONG comparand) noexcept
{
  __atomic_compare_exchange_n(target, &comparand, exchange, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  return comparand;
}
inline std::int64_t InterlockedCompareExchange64(
  volatile std::int64_t* target, const std::int64_t exchange, std::int64_t comparand
) noexcept
{
  __atomic_compare_exchange_n(target, &comparand, exchange, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  return comparand;
}

// --- Memory ------------------------------------------------------------------------------
#define MEM_COMMIT 0x00001000u
#define MEM_RESERVE 0x00002000u
#define MEM_RELEASE 0x00008000u
#define PAGE_READWRITE 0x04u
#define PAGE_NOACCESS 0x01u
LPVOID VirtualAlloc(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect);
BOOL VirtualFree(LPVOID address, SIZE_T size, DWORD freeType);

// --- MSVC CRT names ----------------------------------------------------------------------
using __time64_t = std::int64_t;
inline __time64_t _time64(__time64_t* out) noexcept
{
  const __time64_t now = static_cast<__time64_t>(std::time(nullptr));
  if (out != nullptr) {
    *out = now;
  }
  return now;
}

inline int memcpy_s(void* const dest, const std::size_t destSize, const void* const src, const std::size_t count) noexcept
{
  if (count == 0) {
    return 0;
  }
  if (dest == nullptr || src == nullptr || destSize < count) {
    return 22; // EINVAL / ERANGE, as the CRT's checks
  }
  std::memcpy(dest, src, count);
  return 0;
}

inline int memmove_s(void* const dest, const std::size_t destSize, const void* const src, const std::size_t count) noexcept
{
  if (count == 0) {
    return 0;
  }
  if (dest == nullptr || src == nullptr || destSize < count) {
    return 22;
  }
  std::memmove(dest, src, count);
  return 0;
}
