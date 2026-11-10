#pragma once

// Engine addition (dedicated-server plan WPL.5): the subset of <Windows.h> (and of the
// MSVC CRT) that the shared simulation code uses, for the Linux build. cmake/FafLinux.cmake
// puts this directory on the include path and platform/PosixCompat.h includes it in every
// translation unit; Windows builds never see it. Types and constants have their Windows
// sizes and values. The functions are implemented on POSIX in src/platform/posix/Win32Shim.cpp
// with the Windows semantics the engine relies on: events (manual and auto reset),
// semaphores, mutexes and waits with timeouts on one kind of handle, files opened by
// CreateFile, interlocked operations on 32-bit values, the performance counter, the calling
// thread's id.

#if FAFRE_PLATFORM_WINDOWS
#error "platform/posix/win32/Windows.h is for builds without the Windows SDK"
#endif

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <cwctype>
#include <cerrno>

#include <pthread.h>

#define WINAPI
#define CALLBACK
#define APIENTRY
#define WINBASEAPI

using VOID = void;
using BOOL = int;
using BYTE = std::uint8_t;
using UCHAR = unsigned char;
using CHAR = char;
using WCHAR = wchar_t;
using WORD = std::uint16_t;
using SHORT = std::int16_t;
using USHORT = std::uint16_t;
using DWORD = std::uint32_t;
using UINT = unsigned int;
using INT = int;
using LONG = std::int32_t;
using ULONG = std::uint32_t;
using HRESULT = std::int32_t;
using DWORD_PTR = std::uintptr_t;
using ULONG_PTR = std::uintptr_t;
using UINT_PTR = std::uintptr_t;
using INT_PTR = std::intptr_t;
using LONG_PTR = std::intptr_t;
using SIZE_T = std::size_t;
using HANDLE = void*;
using HMODULE = void*;
using HINSTANCE = void*;
using HLOCAL = void*;
using HWND = void*;
using HDC = void*;
using HFONT = void*;
using LPVOID = void*;
using LPCVOID = const void*;
using LPSTR = char*;
using LPCSTR = const char*;
using LPWSTR = wchar_t*;
using PWSTR = wchar_t*;
struct _GUID
{
  std::uint32_t Data1;
  std::uint16_t Data2;
  std::uint16_t Data3;
  std::uint8_t Data4[8];
};
using GUID = _GUID;
using LPCWSTR = const wchar_t*;
using DWORD64 = std::uint64_t;
using ULONGLONG = std::uint64_t;
using LONGLONG = std::int64_t;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define S_OK (static_cast<HRESULT>(0))
#define E_FAIL (static_cast<HRESULT>(0x80004005u))
#define E_INVALIDARG (static_cast<HRESULT>(0x80070057u))
#define E_NOTIMPL (static_cast<HRESULT>(0x80004001u))
#define E_NOINTERFACE (static_cast<HRESULT>(0x80004002u))
#define SUCCEEDED(hr) (static_cast<HRESULT>(hr) >= 0)
#define FAILED(hr) (static_cast<HRESULT>(hr) < 0)

#define INFINITE 0xFFFFFFFFu
#define WAIT_OBJECT_0 0x00000000u
#define WAIT_ABANDONED 0x00000080u
#define WAIT_TIMEOUT 0x00000102u
#define WAIT_FAILED 0xFFFFFFFFu
#define WAIT_IO_COMPLETION 0x000000C0u
#define INVALID_HANDLE_VALUE (reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-1)))
#define MAX_PATH 260

#define ERROR_SUCCESS 0u
#define NO_ERROR 0u
#define ERROR_FILE_INVALID 1006u
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_PATH_NOT_FOUND 3u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_NOT_SUPPORTED 50u
#define ERROR_FILE_EXISTS 80u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_INSUFFICIENT_BUFFER 122u
#define ERROR_ALREADY_EXISTS 183u
#define ERROR_ENVVAR_NOT_FOUND 203u

struct tagRECT
{
  LONG left;
  LONG top;
  LONG right;
  LONG bottom;
};
using RECT = tagRECT;
struct tagPOINT
{
  LONG x;
  LONG y;
};
using POINT = tagPOINT;
struct tagSIZE
{
  LONG cx;
  LONG cy;
};
using SIZE = tagSIZE;
using HBITMAP = void*;

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

union ULARGE_INTEGER
{
  struct
  {
    DWORD LowPart;
    DWORD HighPart;
  };
  std::uint64_t QuadPart;
};

// -1, 0 or 1 as the first time is earlier than, equal to or later than the second.
inline LONG CompareFileTime(const FILETIME* const first, const FILETIME* const second) noexcept
{
  const std::uint64_t a = (static_cast<std::uint64_t>(first->dwHighDateTime) << 32) | first->dwLowDateTime;
  const std::uint64_t b = (static_cast<std::uint64_t>(second->dwHighDateTime) << 32) | second->dwLowDateTime;
  return a < b ? -1 : (a > b ? 1 : 0);
}

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

struct OSVERSIONINFOW
{
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  WCHAR szCSDVersion[128];
};
#define VER_PLATFORM_WIN32_WINDOWS 1u
#define VER_PLATFORM_WIN32_NT 2u
BOOL GetVersionExW(OSVERSIONINFOW* info);

// --- Synchronisation ---------------------------------------------------------------------
HANDLE CreateEventW(void* attributes, BOOL manualReset, BOOL initialState, const wchar_t* name);
HANDLE CreateEventA(void* attributes, BOOL manualReset, BOOL initialState, const char* name);
#define CreateEvent CreateEventW
HANDLE CreateSemaphoreW(void* attributes, LONG initialCount, LONG maximumCount, const wchar_t* name);
BOOL ReleaseSemaphore(HANDLE semaphore, LONG releaseCount, LONG* previousCount);
HANDLE CreateMutexW(void* attributes, BOOL initialOwner, const wchar_t* name);
HANDLE CreateMutexA(void* attributes, BOOL initialOwner, const char* name);
#define CreateMutex CreateMutexW
BOOL ReleaseMutex(HANDLE mutex);
BOOL SetEvent(HANDLE event);
BOOL ResetEvent(HANDLE event);
DWORD WaitForSingleObject(HANDLE handle, DWORD milliseconds);
DWORD WaitForSingleObjectEx(HANDLE handle, DWORD milliseconds, BOOL alertable);
DWORD WaitForMultipleObjects(DWORD count, const HANDLE* handles, BOOL waitAll, DWORD milliseconds);
BOOL CloseHandle(HANDLE handle);

/// A recursive lock, as Windows' critical section.
struct CRITICAL_SECTION
{
  alignas(16) unsigned char storage[64];
  bool initialized;
};
void InitializeCriticalSection(CRITICAL_SECTION* section);
BOOL InitializeCriticalSectionAndSpinCount(CRITICAL_SECTION* section, DWORD spinCount);
void EnterCriticalSection(CRITICAL_SECTION* section);
BOOL TryEnterCriticalSection(CRITICAL_SECTION* section);
void LeaveCriticalSection(CRITICAL_SECTION* section);
void DeleteCriticalSection(CRITICAL_SECTION* section);

using PVOID = void*;

/// One-time initialisation (InitOnceExecuteOnce's synchronous form).
struct INIT_ONCE
{
  int state; // 0 not run, 1 running, 2 done
};
#define INIT_ONCE_STATIC_INIT {0}
using PINIT_ONCE = INIT_ONCE*;
using PINIT_ONCE_FN = BOOL (*)(PINIT_ONCE initOnce, PVOID parameter, PVOID* context);
BOOL InitOnceExecuteOnce(PINIT_ONCE initOnce, PINIT_ONCE_FN function, PVOID parameter, PVOID* context);

/// The process's command line (/proc/self/cmdline, arguments joined by spaces).
const wchar_t* GetCommandLineW();
const char* GetCommandLineA();

/// A slim reader/writer lock, as a POSIX rwlock (statically initialisable as SRWLOCK_INIT).
struct SRWLOCK
{
  pthread_rwlock_t lock;
};
#define SRWLOCK_INIT {PTHREAD_RWLOCK_INITIALIZER}
inline void InitializeSRWLock(SRWLOCK* const lock) noexcept
{
  (void)::pthread_rwlock_init(&lock->lock, nullptr);
}
inline void AcquireSRWLockExclusive(SRWLOCK* const lock) noexcept
{
  (void)::pthread_rwlock_wrlock(&lock->lock);
}
inline void ReleaseSRWLockExclusive(SRWLOCK* const lock) noexcept
{
  (void)::pthread_rwlock_unlock(&lock->lock);
}
inline void AcquireSRWLockShared(SRWLOCK* const lock) noexcept
{
  (void)::pthread_rwlock_rdlock(&lock->lock);
}
inline void ReleaseSRWLockShared(SRWLOCK* const lock) noexcept
{
  (void)::pthread_rwlock_unlock(&lock->lock);
}

// --- Threads, processes and time ---------------------------------------------------------
DWORD GetCurrentThreadId();
HANDLE GetCurrentThread();
HANDLE GetCurrentProcess();
DWORD GetCurrentProcessId();
// Ends this process at once with `exitCode` (std::_Exit); other processes fail with ERROR_INVALID_HANDLE.
BOOL TerminateProcess(HANDLE process, UINT exitCode);
void Sleep(DWORD milliseconds);
DWORD SleepEx(DWORD milliseconds, BOOL alertable);

// Asynchronous procedure calls: QueueUserAPC queues the call to the thread OpenThread named;
// that thread runs its queued calls, in order, in its next alertable wait (SleepEx,
// WaitForSingleObjectEx with `alertable`), which then returns WAIT_IO_COMPLETION.
#define STANDARD_RIGHTS_REQUIRED 0x000F0000u
#define SYNCHRONIZE 0x00100000u
#define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFFu)
using PAPCFUNC = void (*)(ULONG_PTR parameter);
HANDLE OpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId);
DWORD QueueUserAPC(PAPCFUNC function, HANDLE thread, ULONG_PTR data);

// Shared objects, through the dynamic loader.
HMODULE GetModuleHandleA(const char* moduleName);
HMODULE GetModuleHandleW(const wchar_t* moduleName); // null: the executable's load address
HMODULE LoadLibraryA(const char* fileName);
void* GetProcAddress(HMODULE module, const char* procName);
BOOL FreeLibrary(HMODULE module);
DWORD GetTickCount();
ULONGLONG GetTickCount64();
BOOL QueryPerformanceCounter(LARGE_INTEGER* count);
BOOL QueryPerformanceFrequency(LARGE_INTEGER* frequency);
void GetSystemInfo(SYSTEM_INFO* info);
DWORD GetLastError();
void SetLastError(DWORD error);
BOOL GetProcessAffinityMask(HANDLE process, DWORD_PTR* processMask, DWORD_PTR* systemMask);
DWORD GetEnvironmentVariableA(const char* name, char* buffer, DWORD size);
void OutputDebugStringA(const char* text);
void OutputDebugStringW(const wchar_t* text);

#define THREAD_PRIORITY_LOWEST (-2)
#define THREAD_PRIORITY_BELOW_NORMAL (-1)
#define THREAD_PRIORITY_NORMAL 0
#define THREAD_PRIORITY_ABOVE_NORMAL 1
#define THREAD_PRIORITY_HIGHEST 2
#define THREAD_PRIORITY_TIME_CRITICAL 15
#define THREAD_PRIORITY_IDLE (-15)
BOOL SetThreadPriority(HANDLE thread, int priority);
DWORD_PTR SetThreadAffinityMask(HANDLE thread, DWORD_PTR mask);

enum LOGICAL_PROCESSOR_RELATIONSHIP
{
  RelationProcessorCore = 0,
  RelationNumaNode = 1,
  RelationCache = 2,
  RelationProcessorPackage = 3,
  RelationGroup = 4,
  RelationAll = 0xFFFF,
};
struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;
/// Physical cores and NUMA nodes from sysfs, as fixed-size records in group 0. With no topology to
/// report: FALSE with ERROR_NOT_SUPPORTED and a length of 0.
BOOL GetLogicalProcessorInformationEx(
  LOGICAL_PROCESSOR_RELATIONSHIP relation, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* buffer, DWORD* length
);

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
#define MEM_TOP_DOWN 0x00100000u
#define MEM_FREE 0x00010000u
#define MEM_RELEASE 0x00008000u
#define MEM_PRIVATE 0x00020000u
#define PAGE_NOACCESS 0x01u
#define PAGE_READONLY 0x02u
#define PAGE_READWRITE 0x04u
LPVOID VirtualAlloc(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect);
BOOL VirtualFree(LPVOID address, SIZE_T size, DWORD freeType);

struct MEMORY_BASIC_INFORMATION
{
  LPVOID BaseAddress;
  LPVOID AllocationBase;
  DWORD AllocationProtect;
  SIZE_T RegionSize;
  DWORD State;
  DWORD Protect;
  DWORD Type;
};
/// Describes the page holding `address` from /proc/self/maps: committed private
/// read-write memory, read-only, or free.
SIZE_T VirtualQuery(LPCVOID address, MEMORY_BASIC_INFORMATION* info, SIZE_T length);

HLOCAL LocalFree(HLOCAL memory);

// --- Files -------------------------------------------------------------------------------
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 0x00000001u
#define FILE_SHARE_WRITE 0x00000002u
#define FILE_SHARE_DELETE 0x00000004u
#define CREATE_NEW 1u
#define CREATE_ALWAYS 2u
#define OPEN_EXISTING 3u
#define OPEN_ALWAYS 4u
#define TRUNCATE_EXISTING 5u
#define FILE_ATTRIBUTE_READONLY 0x00000001u
#define FILE_ATTRIBUTE_HIDDEN 0x00000002u
#define FILE_ATTRIBUTE_SYSTEM 0x00000004u
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010u
#define FILE_ATTRIBUTE_ARCHIVE 0x00000020u
#define FILE_ATTRIBUTE_NORMAL 0x00000080u
#define FILE_FLAG_SEQUENTIAL_SCAN 0x08000000u
#define FILE_FLAG_RANDOM_ACCESS 0x10000000u
#define FILE_FLAG_OVERLAPPED 0x40000000u
#define FILE_FLAG_NO_BUFFERING 0x20000000u

// The multimedia timer's resolution (timeapi.h): Linux timers and sleeps are already fine-grained,
// so raising it always succeeds and changes nothing.
#define TIMERR_NOERROR 0u
inline UINT timeBeginPeriod(const UINT period) noexcept
{
  (void)period;
  return TIMERR_NOERROR;
}
inline UINT timeEndPeriod(const UINT period) noexcept
{
  (void)period;
  return TIMERR_NOERROR;
}

// A Win32 error as an HRESULT (FACILITY_WIN32).
inline HRESULT HRESULT_FROM_WIN32(const unsigned long error) noexcept
{
  return static_cast<HRESULT>(error) <= 0 ? static_cast<HRESULT>(error)
                                          : static_cast<HRESULT>((error & 0x0000FFFFu) | (7u << 16) | 0x80000000u);
}

// BMP file headers (wingdi.h), with the Windows layout: the frame and texture dumps write them.
#pragma pack(push, 2)
struct BITMAPFILEHEADER
{
  WORD bfType;
  DWORD bfSize;
  WORD bfReserved1;
  WORD bfReserved2;
  DWORD bfOffBits;
};
#pragma pack(pop)
struct BITMAPINFOHEADER
{
  DWORD biSize;
  LONG biWidth;
  LONG biHeight;
  WORD biPlanes;
  WORD biBitCount;
  DWORD biCompression;
  DWORD biSizeImage;
  LONG biXPelsPerMeter;
  LONG biYPelsPerMeter;
  DWORD biClrUsed;
  DWORD biClrImportant;
};
#define BI_RGB 0u
static_assert(sizeof(BITMAPFILEHEADER) == 14, "BITMAPFILEHEADER has its Windows size");
static_assert(sizeof(BITMAPINFOHEADER) == 40, "BITMAPINFOHEADER has its Windows size");

// GetFileInformationByHandleEx(FileStorageInfo): the sector sizes unbuffered reads align to. The
// POSIX files read through the page cache, so there is no sector size to report: it fails, and
// callers keep their defaults.
enum FILE_INFO_BY_HANDLE_CLASS
{
  FileStorageInfo = 16
};
struct FILE_STORAGE_INFO
{
  ULONG LogicalBytesPerSector;
  ULONG PhysicalBytesPerSectorForAtomicity;
  ULONG PhysicalBytesPerSectorForPerformance;
  ULONG FileSystemEffectivePhysicalBytesPerSectorForAtomicity;
  ULONG Flags;
  ULONG ByteOffsetForSectorAlignment;
  ULONG ByteOffsetForPartitionAlignment;
};
inline BOOL GetFileInformationByHandleEx(HANDLE, FILE_INFO_BY_HANDLE_CLASS, void*, DWORD) noexcept
{
  return FALSE;
}
#define FILE_FLAG_BACKUP_SEMANTICS 0x02000000u
#define FILE_BEGIN 0u
#define FILE_CURRENT 1u
#define FILE_END 2u
#define INVALID_FILE_SIZE 0xFFFFFFFFu
#define INVALID_SET_FILE_POINTER 0xFFFFFFFFu
#define INVALID_FILE_ATTRIBUTES 0xFFFFFFFFu
#define MOVEFILE_REPLACE_EXISTING 0x00000001u
BOOL ReplaceFileW(const wchar_t* replacedFile, const wchar_t* replacementFile, const wchar_t* backupFile, DWORD flags, void* exclude, void* reserved);
BOOL PathFileExistsW(const wchar_t* path);

// Heaps: every heap is the C library's (HeapSize is malloc_usable_size, at least the
// requested size).
#define HEAP_ZERO_MEMORY 0x00000008u
HANDLE GetProcessHeap();
HANDLE HeapCreate(DWORD options, SIZE_T initialSize, SIZE_T maximumSize);
void* HeapAlloc(HANDLE heap, DWORD flags, SIZE_T bytes);
BOOL HeapFree(HANDLE heap, DWORD flags, void* memory);
SIZE_T HeapSize(HANDLE heap, DWORD flags, const void* memory);
BOOL CreateDirectoryA(const char* path, void* attributes);
/// `_fullpath`: the absolute, lexically normalised form of `path` (which need not exist).
char* _fullpath(char* absolutePath, const char* relativePath, std::size_t maxLength);
/// Plan WPR.23 (headless `--path-spelling`): from now on `file` gets one `requested<TAB>on disk` line
/// for each path found on disk only by ignoring case, each once.
void FAF_SetPathSpellingTrace(std::FILE* file);

// Code pages: the ANSI and OEM code pages are UTF-8 here.
#define CP_ACP 0u
#define CP_OEMCP 1u
#define CP_UTF8 65001u
int WideCharToMultiByte(UINT codePage, DWORD flags, const wchar_t* wide, int wideLength, char* multiByte, int multiByteLength, const char* defaultChar, BOOL* usedDefaultChar);
int MultiByteToWideChar(UINT codePage, DWORD flags, const char* multiByte, int multiByteLength, wchar_t* wide, int wideLength);
// The secure scanf takes a buffer size after each %s, %c and %[ argument; the shared code
// scans numbers only, where it is sscanf.
#define sscanf_s sscanf
DWORD GetModuleFileNameW(HMODULE module, wchar_t* fileName, DWORD size);
BOOL SetProcessAffinityMask(HANDLE process, DWORD_PTR processMask);

// The shell folders, as the XDG directories: CSIDL_LOCAL_APPDATA is $XDG_DATA_HOME
// (~/.local/share), CSIDL_APPDATA $XDG_CONFIG_HOME (~/.config), CSIDL_PERSONAL ~/Documents,
// CSIDL_DESKTOPDIRECTORY ~/Desktop; other folders fail with E_FAIL.
#define CSIDL_DESKTOP 0x0000
#define CSIDL_PERSONAL 0x0005
#define CSIDL_DESKTOPDIRECTORY 0x0010
#define CSIDL_APPDATA 0x001A
#define CSIDL_LOCAL_APPDATA 0x001C
#define CSIDL_FLAG_CREATE 0x8000
HRESULT SHGetFolderPathW(HWND owner, int folder, HANDLE token, DWORD flags, wchar_t* path);

// Shell file operations are not available: SHFileOperation fails with ERROR_NOT_SUPPORTED and
// touches nothing.
#define FO_MOVE 0x0001u
#define FO_COPY 0x0002u
#define FO_DELETE 0x0003u
#define FO_RENAME 0x0004u
#define FOF_SILENT 0x0004u
#define FOF_NOCONFIRMATION 0x0010u
#define FOF_ALLOWUNDO 0x0040u
#define FOF_NOERRORUI 0x0400u
struct SHFILEOPSTRUCTA
{
  HWND hwnd;
  UINT wFunc;
  const char* pFrom;
  const char* pTo;
  WORD fFlags;
  BOOL fAnyOperationsAborted;
  void* hNameMappings;
  const char* lpszProgressTitle;
};
struct SHFILEOPSTRUCTW
{
  HWND hwnd;
  UINT wFunc;
  const wchar_t* pFrom;
  const wchar_t* pTo;
  WORD fFlags;
  BOOL fAnyOperationsAborted;
  void* hNameMappings;
  const wchar_t* lpszProgressTitle;
};
int SHFileOperationA(SHFILEOPSTRUCTA* operation);
int SHFileOperationW(SHFILEOPSTRUCTW* operation);
#define MOVEFILE_COPY_ALLOWED 0x00000002u
#define MOVEFILE_WRITE_THROUGH 0x00000008u

HANDLE CreateFileW(
  const wchar_t* path, DWORD desiredAccess, DWORD shareMode, void* security, DWORD creation, DWORD flags, HANDLE templateFile
);
HANDLE CreateFileA(
  const char* path, DWORD desiredAccess, DWORD shareMode, void* security, DWORD creation, DWORD flags, HANDLE templateFile
);
BOOL ReadFile(HANDLE file, void* buffer, DWORD bytesToRead, DWORD* bytesRead, void* overlapped);
BOOL WriteFile(HANDLE file, const void* buffer, DWORD bytesToWrite, DWORD* bytesWritten, void* overlapped);
BOOL SetFilePointerEx(HANDLE file, LARGE_INTEGER distance, LARGE_INTEGER* newPosition, DWORD moveMethod);
DWORD SetFilePointer(HANDLE file, LONG distance, LONG* distanceHigh, DWORD moveMethod);
BOOL GetFileSizeEx(HANDLE file, LARGE_INTEGER* size);
DWORD GetFileSize(HANDLE file, DWORD* sizeHigh);
BOOL FlushFileBuffers(HANDLE file);
// Read-only views of a whole file (the only mapping the shared code makes).
#define FILE_MAP_READ 0x0004u
HANDLE CreateFileMappingW(HANDLE file, void* attributes, DWORD protect, DWORD maximumSizeHigh, DWORD maximumSizeLow, const wchar_t* name);
void* MapViewOfFile(HANDLE mapping, DWORD desiredAccess, DWORD offsetHigh, DWORD offsetLow, std::size_t bytes);
BOOL UnmapViewOfFile(const void* view);
BOOL SetEndOfFile(HANDLE file);
DWORD GetFileAttributesW(const wchar_t* path);
DWORD GetFileAttributesA(const char* path);
BOOL MoveFileExW(const wchar_t* from, const wchar_t* to, DWORD flags);
BOOL MoveFileExA(const char* from, const char* to, DWORD flags);
BOOL CopyFileW(const wchar_t* from, const wchar_t* to, BOOL failIfExists);
BOOL MoveFileW(const wchar_t* from, const wchar_t* to);
BOOL DeleteFileW(const wchar_t* path);
BOOL DeleteFileA(const char* path);
BOOL CreateDirectoryW(const wchar_t* path, void* security);
BOOL DosDateTimeToFileTime(WORD fatDate, WORD fatTime, FILETIME* fileTime);

// --- Messages ----------------------------------------------------------------------------
#define FORMAT_MESSAGE_ALLOCATE_BUFFER 0x00000100u
#define FORMAT_MESSAGE_IGNORE_INSERTS 0x00000200u
#define FORMAT_MESSAGE_FROM_STRING 0x00000400u
#define FORMAT_MESSAGE_FROM_HMODULE 0x00000800u
#define FORMAT_MESSAGE_FROM_SYSTEM 0x00001000u
#define FORMAT_MESSAGE_ARGUMENT_ARRAY 0x00002000u
#define FORMAT_MESSAGE_MAX_WIDTH_MASK 0x000000FFu
#define LANG_NEUTRAL 0x00
#define SUBLANG_DEFAULT 0x01
#define MAKELANGID(p, s) ((static_cast<WORD>(s) << 10) | static_cast<WORD>(p))
/// FORMAT_MESSAGE_FROM_SYSTEM: the text of `messageId` read as an errno value (strerror),
/// the only source the engine formats from.
DWORD FormatMessageW(DWORD flags, const void* source, DWORD messageId, DWORD languageId, wchar_t* buffer, DWORD size, va_list* arguments);
DWORD FormatMessageA(DWORD flags, const void* source, DWORD messageId, DWORD languageId, char* buffer, DWORD size, va_list* arguments);

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
char* _ctime64(const __time64_t* time) noexcept;

struct __timeb64
{
  __time64_t time;
  unsigned short millitm;
  short timezone;
  short dstflag;
};
void _ftime64(__timeb64* out) noexcept;
inline int _ftime64_s(__timeb64* out) noexcept
{
  _ftime64(out);
  return 0;
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

int fopen_s(std::FILE** file, const char* path, const char* mode) noexcept;
int _wfopen_s(std::FILE** file, const wchar_t* path, const wchar_t* mode) noexcept;

int strncpy_s(char* dest, std::size_t destSize, const char* src, std::size_t count) noexcept;
template <std::size_t N>
inline int strncpy_s(char (&dest)[N], const char* const src, const std::size_t count) noexcept
{
  return strncpy_s(dest, N, src, count);
}
int strcpy_s(char* dest, std::size_t destSize, const char* src) noexcept;
template <std::size_t N>
inline int strcpy_s(char (&dest)[N], const char* const src) noexcept
{
  return strcpy_s(dest, N, src);
}
int sprintf_s(char* buffer, std::size_t size, const char* format, ...) noexcept;
template <std::size_t N, class... Args>
inline int sprintf_s(char (&buffer)[N], const char* const format, Args... args) noexcept
{
  return sprintf_s(buffer, N, format, args...);
}
int vsprintf_s(char* buffer, std::size_t size, const char* format, va_list arguments) noexcept;
#define _TRUNCATE (static_cast<std::size_t>(-1))

int _memicmp(const void* lhs, const void* rhs, std::size_t count) noexcept;

using _locale_t = void*;
inline wint_t _towlower_l(const wint_t c, _locale_t) noexcept
{
  return std::towlower(c);
}

// x87 control word (float.h on Windows).
#define _MCW_PC 0x00030000u
#define _PC_64 0x00000000u
#define _PC_53 0x00010000u
#define _PC_24 0x00020000u
#define _MCW_RC 0x00000300u
#define _RC_NEAR 0x00000000u
#define _MCW_EM 0x0008001Fu
/// The x87 and SSE control state in the CRT's encoding; changes the x87 precision and
/// rounding fields of the calling thread's control word.
unsigned int _controlfp(unsigned int newValue, unsigned int mask) noexcept;

// --- More of the same, found by the Linux build ----------------------------------------
#define PAGE_WRITECOPY 0x08u
#define PAGE_EXECUTE 0x10u
#define PAGE_EXECUTE_READ 0x20u
#define PAGE_EXECUTE_READWRITE 0x40u
#define PAGE_EXECUTE_WRITECOPY 0x80u
#define PAGE_GUARD 0x100u
#define MEM_DECOMMIT 0x00004000u
#define MEM_MAPPED 0x00040000u
#define MEM_IMAGE 0x01000000u

#define DLL_PROCESS_DETACH 0
#define DLL_PROCESS_ATTACH 1
#define DLL_THREAD_ATTACH 2
#define DLL_THREAD_DETACH 3

struct SYSTEMTIME
{
  WORD wYear;
  WORD wMonth;
  WORD wDayOfWeek;
  WORD wDay;
  WORD wHour;
  WORD wMinute;
  WORD wSecond;
  WORD wMilliseconds;
};
void GetSystemTimeAsFileTime(FILETIME* fileTime);
BOOL FileTimeToLocalFileTime(const FILETIME* fileTime, FILETIME* localFileTime);
BOOL FileTimeToSystemTime(const FILETIME* fileTime, SYSTEMTIME* systemTime);
void GetLocalTime(SYSTEMTIME* systemTime);
void GetSystemTime(SYSTEMTIME* systemTime);

enum GET_FILEEX_INFO_LEVELS
{
  GetFileExInfoStandard = 0,
  GetFileExMaxInfoLevel = 1,
};
struct WIN32_FILE_ATTRIBUTE_DATA
{
  DWORD dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD nFileSizeHigh;
  DWORD nFileSizeLow;
};
BOOL GetFileAttributesExW(const wchar_t* path, GET_FILEEX_INFO_LEVELS level, void* information);
BOOL GetFileAttributesExA(const char* path, GET_FILEEX_INFO_LEVELS level, void* information);

// Directory search: the last component of the name is a '*'/'?' wildcard, matched without regard
// to case as on Windows; the folder part goes through the shim's case resolution.
struct WIN32_FIND_DATAA
{
  DWORD dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD nFileSizeHigh;
  DWORD nFileSizeLow;
  DWORD dwReserved0;
  DWORD dwReserved1;
  char cFileName[MAX_PATH];
  char cAlternateFileName[14];
};
HANDLE FindFirstFileA(const char* fileName, WIN32_FIND_DATAA* found);
BOOL FindNextFileA(HANDLE search, WIN32_FIND_DATAA* found);
struct WIN32_FIND_DATAW
{
  DWORD dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD nFileSizeHigh;
  DWORD nFileSizeLow;
  DWORD dwReserved0;
  DWORD dwReserved1;
  wchar_t cFileName[MAX_PATH];
  wchar_t cAlternateFileName[14];
};
// The A search with UTF-8 names, widened (wchar_t is UTF-32 here).
HANDLE FindFirstFileW(const wchar_t* fileName, WIN32_FIND_DATAW* found);
BOOL FindNextFileW(HANDLE search, WIN32_FIND_DATAW* found);
BOOL FindClose(HANDLE search);
#define ERROR_NO_MORE_FILES 18u

using KAFFINITY = std::uintptr_t;
struct GROUP_AFFINITY
{
  KAFFINITY Mask;
  WORD Group;
  WORD Reserved[3];
};
struct PROCESSOR_NUMBER
{
  WORD Group;
  BYTE Number;
  BYTE Reserved;
};
struct PROCESSOR_RELATIONSHIP
{
  BYTE Flags;
  BYTE EfficiencyClass;
  BYTE Reserved[20];
  WORD GroupCount;
  GROUP_AFFINITY GroupMask[1];
};
struct NUMA_NODE_RELATIONSHIP
{
  DWORD NodeNumber;
  BYTE Reserved[18];
  WORD GroupCount;
  GROUP_AFFINITY GroupMask;
};
struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
{
  LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
  DWORD Size;
  union
  {
    PROCESSOR_RELATIONSHIP Processor;
    NUMA_NODE_RELATIONSHIP NumaNode;
  };
};
void GetCurrentProcessorNumberEx(PROCESSOR_NUMBER* number);
// One processor group (group 0, the CPUs the kernel numbers 0..63): the group affinity is
// the thread's affinity mask, and the ideal processor is a hint Linux has no call for.
BOOL SetThreadGroupAffinity(HANDLE thread, const GROUP_AFFINITY* affinity, GROUP_AFFINITY* previous);
BOOL SetThreadIdealProcessorEx(HANDLE thread, PROCESSOR_NUMBER* ideal, PROCESSOR_NUMBER* previous);
BOOL GetNumaProcessorNode(UCHAR processor, UCHAR* nodeNumber);
BOOL GetNumaNodeProcessorMask(UCHAR node, ULONGLONG* processorMask);

int _vsnprintf(char* buffer, std::size_t count, const char* format, va_list arguments) noexcept;
int _vsnwprintf(wchar_t* buffer, std::size_t count, const wchar_t* format, va_list arguments) noexcept;
int _snprintf(char* buffer, std::size_t count, const char* format, ...) noexcept;
inline std::tm* _localtime64(const __time64_t* const time) noexcept
{
  const std::time_t value = static_cast<std::time_t>(*time);
  return std::localtime(&value);
}
inline std::tm* _gmtime64(const __time64_t* const time) noexcept
{
  const std::time_t value = static_cast<std::time_t>(*time);
  return std::gmtime(&value);
}
inline __time64_t _mktime64(std::tm* const brokenDown) noexcept
{
  return static_cast<__time64_t>(std::mktime(brokenDown));
}
inline std::FILE* _popen(const char* const command, const char* const mode) noexcept
{
  return ::popen(command, mode);
}
inline int _pclose(std::FILE* const stream) noexcept
{
  return ::pclose(stream);
}
inline int* _errno() noexcept
{
  return &errno;
}

// The calling thread's return addresses, skipping the innermost `skip` frames (this function's
// own frame not counted), as Windows' RtlCaptureStackBackTrace; no hash.
USHORT RtlCaptureStackBackTrace(DWORD skip, DWORD count, void** frames, DWORD* hash);

// The MSVC CRT's getenv_s: *required is the value's length with its terminator, 0 when the
// variable is unset (the buffer then holds ""); ERANGE when the buffer is too small for it. A null
// buffer with size 0 only asks for the length.
inline int getenv_s(std::size_t* const required, char* const buffer, const std::size_t size, const char* const name) noexcept
{
  const char* const value = name != nullptr ? std::getenv(name) : nullptr;
  if (value == nullptr) {
    if (required != nullptr) {
      *required = 0;
    }
    if (buffer != nullptr && size > 0u) {
      buffer[0] = '\0';
    }
    return 0;
  }
  const std::size_t needed = std::strlen(value) + 1u;
  if (required != nullptr) {
    *required = needed;
  }
  if (buffer == nullptr && size == 0u) {
    return 0;
  }
  if (buffer == nullptr || size < needed) {
    if (buffer != nullptr && size > 0u) {
      buffer[0] = '\0';
    }
    return ERANGE;
  }
  std::memcpy(buffer, value, needed);
  return 0;
}

// --- Windows, cursor and keyboard state (WinUser.h) for the Linux client (issue #255) ---------
// The client's UI code works with window handles: it reads and moves the cursor, captures the
// mouse during drags, measures the main window and asks for key states. On Linux a window handle
// is the window system's own (issue #256, SDL3), and src/platform/posix/Win32WindowPosix.cpp
// answers these calls from what that system reports. Only the client links that file; the
// simulation never calls them.
using HCURSOR = void*;
using HICON = void*;
using HMONITOR = void*;
using HMENU = void*;

BOOL GetCursorPos(POINT* point);
BOOL SetCursorPos(int x, int y);
BOOL GetWindowRect(HWND window, RECT* rect);
BOOL GetClientRect(HWND window, RECT* rect);
BOOL ScreenToClient(HWND window, POINT* point);
BOOL ClientToScreen(HWND window, POINT* point);
HWND SetCapture(HWND window);
BOOL ReleaseCapture();
HWND GetCapture();
HWND SetFocus(HWND window);
HWND GetFocus();
// The window that has the user's input: the focused one, as the window system reports it.
HWND GetForegroundWindow();
// A debugger (ptrace tracer) is attached; TracerPid in /proc/self/status.
BOOL IsDebuggerPresent();
void DebugBreak();
BOOL ShowWindow(HWND window, int command);
BOOL IsWindowVisible(HWND window);
BOOL SetWindowPos(HWND window, HWND insertAfter, int x, int y, int width, int height, UINT flags);
#define HWND_TOP (reinterpret_cast<HWND>(0))
#define HWND_BOTTOM (reinterpret_cast<HWND>(1))
#define HWND_TOPMOST (reinterpret_cast<HWND>(-1))
#define HWND_NOTOPMOST (reinterpret_cast<HWND>(-2))
#define SWP_NOSIZE 0x0001u
#define SWP_NOMOVE 0x0002u
#define SWP_NOZORDER 0x0004u
#define SWP_NOACTIVATE 0x0010u
#define SWP_FRAMECHANGED 0x0020u
#define SWP_SHOWWINDOW 0x0040u
#define SW_HIDE 0
#define SW_SHOWNORMAL 1
#define SW_SHOWMINIMIZED 2
#define SW_SHOWMAXIMIZED 3
#define SW_SHOW 5
#define SW_MINIMIZE 6
#define SW_RESTORE 9
// Waits for the handles or for window-system events, as Windows waits for them or for window
// messages: WAIT_OBJECT_0 + count means the window system has events (it calls
// platform::posix::WakeMessageWait, Win32WindowPosix.h). The wake and flag masks are not used.
DWORD MsgWaitForMultipleObjectsEx(DWORD count, const HANDLE* handles, DWORD milliseconds, DWORD wakeMask, DWORD flags);
SHORT GetKeyState(int virtualKey);
SHORT GetAsyncKeyState(int virtualKey);
HCURSOR SetCursor(HCURSOR cursor);
int ShowCursor(BOOL show);
// Frees a cursor the window system made (platform::posix::gCreateCursorHook).
BOOL DestroyIcon(HICON icon);
// Confines the cursor to `rect` (screen coordinates), or frees it for null.
BOOL ClipCursor(const RECT* rect);
// Monitors, as the window system reports them (platform::posix::SetMonitors, Win32WindowPosix.h);
// MonitorFromPoint fails while none is known.
struct MONITORINFO
{
  DWORD cbSize;
  RECT rcMonitor;
  RECT rcWork;
  DWORD dwFlags;
};
#define MONITOR_DEFAULTTONULL 0x0u
#define MONITOR_DEFAULTTOPRIMARY 0x1u
#define MONITOR_DEFAULTTONEAREST 0x2u
#define MONITORINFOF_PRIMARY 0x1u
HMONITOR MonitorFromPoint(POINT point, DWORD flags);
BOOL GetMonitorInfoW(HMONITOR monitor, MONITORINFO* info);
// Window state the main loop and the title bar use, answered from the window system's reports.
BOOL IsIconic(HWND window);
#define GA_PARENT 1u
#define GA_ROOT 2u
#define GA_ROOTOWNER 3u
// The window system's windows are top-level: the root of a window is the window itself.
HWND GetAncestor(HWND window, UINT flags);
BOOL SetWindowTextA(HWND window, const char* text);
BOOL SetWindowTextW(HWND window, const wchar_t* text);
// System settings: the screensaver switch goes to the window system; font smoothing reads 0.
#define SPI_GETSCREENSAVEACTIVE 0x0010u
#define SPI_SETSCREENSAVEACTIVE 0x0011u
#define SPI_GETFONTSMOOTHING 0x004Au
#define SPI_GETFONTSMOOTHINGTYPE 0x200Au
#define SPI_GETFONTSMOOTHINGCONTRAST 0x200Cu
#define SPI_GETFONTSMOOTHINGORIENTATION 0x2012u
BOOL SystemParametersInfoW(UINT action, UINT parameter, void* data, UINT winIni);
// Message boxes go to the window system (platform::posix::gMessageBoxHook); without one the text
// goes to stderr and the box answers as if closed: IDOK, or IDNO for a yes/no box.
#define MB_OK 0x0u
#define MB_YESNO 0x4u
#define MB_TYPEMASK 0xFu
#define IDOK 1
#define IDCANCEL 2
#define IDYES 6
#define IDNO 7
int MessageBoxW(HWND window, const wchar_t* text, const wchar_t* caption, UINT type);

// Registry value types, for the code that names them; the Linux client has no registry.
#define REG_SZ 1u
#define REG_DWORD 4u

// --- GDI text (WinGDI.h) for the Linux client (issue #255) ------------------------------------
// CD3DFont rasterizes a character's glyph with GDI into a 32-bit scratch bitmap and reads its
// metrics and kerning pairs. src/platform/posix/GdiOverFreeType.cpp answers the same calls with
// FreeType, from the font files the game registers with AddFontMemResourceEx. Only the client
// links that file.
using HGDIOBJ = void*;
using HBRUSH = void*;
using COLORREF = DWORD;
#define RGB(r, g, b) \
  (static_cast<COLORREF>( \
    static_cast<BYTE>(r) | (static_cast<WORD>(static_cast<BYTE>(g)) << 8) | (static_cast<DWORD>(static_cast<BYTE>(b)) << 16) \
  ))
#define GDI_ERROR 0xFFFFFFFFu
#define LF_FACESIZE 32
#define TMPF_FIXED_PITCH 0x01u
#define TMPF_VECTOR 0x02u
#define TMPF_TRUETYPE 0x04u
#define BLACK_BRUSH 4
#define TA_BASELINE 24u
#define DT_SINGLELINE 0x0020u
#define DT_NOCLIP 0x0100u
#define DT_CALCRECT 0x0400u
#define DT_NOPREFIX 0x0800u
#define FW_NORMAL 400
#define FW_BOLD 700
struct TEXTMETRICW
{
  LONG tmHeight;
  LONG tmAscent;
  LONG tmDescent;
  LONG tmInternalLeading;
  LONG tmExternalLeading;
  LONG tmAveCharWidth;
  LONG tmMaxCharWidth;
  LONG tmWeight;
  LONG tmOverhang;
  LONG tmDigitizedAspectX;
  LONG tmDigitizedAspectY;
  WCHAR tmFirstChar;
  WCHAR tmLastChar;
  WCHAR tmDefaultChar;
  WCHAR tmBreakChar;
  BYTE tmItalic;
  BYTE tmUnderlined;
  BYTE tmStruckOut;
  BYTE tmPitchAndFamily;
  BYTE tmCharSet;
};
struct KERNINGPAIR
{
  WORD wFirst;
  WORD wSecond;
  int iKernAmount;
};
struct BITMAP
{
  LONG bmType;
  LONG bmWidth;
  LONG bmHeight;
  LONG bmWidthBytes;
  WORD bmPlanes;
  WORD bmBitsPixel;
  LPVOID bmBits;
};
HANDLE AddFontMemResourceEx(void* fontData, DWORD size, void* reserved, DWORD* fontCount);
BOOL RemoveFontMemResourceEx(HANDLE fontHandle);
HFONT CreateFontA(
  int height, int width, int escapement, int orientation, int weight, DWORD italic, DWORD underline, DWORD strikeOut,
  DWORD charSet, DWORD outPrecision, DWORD clipPrecision, DWORD quality, DWORD pitchAndFamily, const char* faceName
);
HDC CreateCompatibleDC(HDC dc);
HBITMAP CreateBitmap(int width, int height, UINT planes, UINT bitsPerPixel, const void* bits);
HGDIOBJ SelectObject(HDC dc, HGDIOBJ object);
BOOL DeleteObject(HGDIOBJ object);
BOOL DeleteDC(HDC dc);
HGDIOBJ GetStockObject(int object);
int GetObjectW(HGDIOBJ object, int size, void* out);
BOOL GetTextMetricsW(HDC dc, TEXTMETRICW* metrics);
int GetTextFaceW(HDC dc, int count, wchar_t* face);
DWORD GetFontData(HDC dc, DWORD table, DWORD offset, void* buffer, DWORD size);
DWORD GetKerningPairsW(HDC dc, DWORD count, KERNINGPAIR* pairs);
UINT SetTextAlign(HDC dc, UINT align);
COLORREF SetTextColor(HDC dc, COLORREF color);
COLORREF SetBkColor(HDC dc, COLORREF color);
int FillRect(HDC dc, const RECT* rect, HBRUSH brush);
int DrawTextW(HDC dc, const wchar_t* text, int count, RECT* rect, UINT format);
COLORREF GetPixel(HDC dc, int x, int y);
LONG GetBitmapBits(HBITMAP bitmap, LONG size, void* bits);
BOOL GdiFlush();

// Virtual-key codes (WinUser.h), with their Windows values: the client's key bindings
// convert wx key codes to and from them (wxCharCodeWXToMSW, issue #255).
#define VK_LBUTTON 0x01
#define VK_RBUTTON 0x02
#define VK_CANCEL 0x03
#define VK_MBUTTON 0x04
#define VK_BACK 0x08
#define VK_TAB 0x09
#define VK_CLEAR 0x0C
#define VK_RETURN 0x0D
#define VK_SHIFT 0x10
#define VK_CONTROL 0x11
#define VK_MENU 0x12
#define VK_PAUSE 0x13
#define VK_CAPITAL 0x14
#define VK_ESCAPE 0x1B
#define VK_SPACE 0x20
#define VK_PRIOR 0x21
#define VK_NEXT 0x22
#define VK_END 0x23
#define VK_HOME 0x24
#define VK_LEFT 0x25
#define VK_UP 0x26
#define VK_RIGHT 0x27
#define VK_DOWN 0x28
#define VK_SELECT 0x29
#define VK_PRINT 0x2A
#define VK_EXECUTE 0x2B
#define VK_SNAPSHOT 0x2C
#define VK_INSERT 0x2D
#define VK_DELETE 0x2E
#define VK_HELP 0x2F
#define VK_LWIN 0x5B
#define VK_RWIN 0x5C
#define VK_APPS 0x5D
#define VK_NUMPAD0 0x60
#define VK_NUMPAD1 0x61
#define VK_NUMPAD2 0x62
#define VK_NUMPAD3 0x63
#define VK_NUMPAD4 0x64
#define VK_NUMPAD5 0x65
#define VK_NUMPAD6 0x66
#define VK_NUMPAD7 0x67
#define VK_NUMPAD8 0x68
#define VK_NUMPAD9 0x69
#define VK_MULTIPLY 0x6A
#define VK_ADD 0x6B
#define VK_SEPARATOR 0x6C
#define VK_SUBTRACT 0x6D
#define VK_DECIMAL 0x6E
#define VK_DIVIDE 0x6F
#define VK_F1 0x70
#define VK_F2 0x71
#define VK_F3 0x72
#define VK_F4 0x73
#define VK_F5 0x74
#define VK_F6 0x75
#define VK_F7 0x76
#define VK_F8 0x77
#define VK_F9 0x78
#define VK_F10 0x79
#define VK_F11 0x7A
#define VK_F12 0x7B
#define VK_F13 0x7C
#define VK_F14 0x7D
#define VK_F15 0x7E
#define VK_F16 0x7F
#define VK_F17 0x80
#define VK_F18 0x81
#define VK_F19 0x82
#define VK_F20 0x83
#define VK_F21 0x84
#define VK_F22 0x85
#define VK_F23 0x86
#define VK_F24 0x87
#define VK_NUMLOCK 0x90
#define VK_SCROLL 0x91
#define VK_LSHIFT 0xA0
#define VK_RSHIFT 0xA1
#define VK_LCONTROL 0xA2
#define VK_RCONTROL 0xA3
#define VK_LMENU 0xA4
#define VK_RMENU 0xA5
#define VK_OEM_1 0xBA
#define VK_OEM_PLUS 0xBB
#define VK_OEM_COMMA 0xBC
#define VK_OEM_MINUS 0xBD
#define VK_OEM_PERIOD 0xBE
#define VK_OEM_2 0xBF
#define VK_OEM_3 0xC0
#define VK_OEM_4 0xDB
#define VK_OEM_5 0xDC
#define VK_OEM_6 0xDD
#define VK_OEM_7 0xDE
