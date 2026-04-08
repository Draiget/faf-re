#include <Windows.h>
#include <d3d9.h>
#include <mmsystem.h>
#include <processenv.h>
#include <dsound.h>

extern "C" __declspec(dllimport) LPCH WINAPI GetEnvironmentStringsA(void);

namespace moho::runtime
{
  /**
   * Address: 0x00B57BB6 (FUN_00B57BB6)
   *
   * What it does:
   * Import thunk that forwards to `GetStringTypeA`.
   */
  BOOL ThunkGetStringTypeA(
    const LCID locale,
    const DWORD infoType,
    LPCSTR src,
    const int srcLength,
    LPWORD charType
  )
  {
    return ::GetStringTypeA(locale, infoType, src, srcLength, charType);
  }

  /**
   * Address: 0x00B57BBC (FUN_00B57BBC)
   *
   * What it does:
   * Import thunk that forwards to `GetStringTypeW`.
   */
  BOOL ThunkGetStringTypeW(const DWORD infoType, LPCWCH src, const int srcLength, LPWORD charType)
  {
    return ::GetStringTypeW(infoType, src, srcLength, charType);
  }

  /**
   * Address: 0x00B57BC2 (FUN_00B57BC2)
   *
   * What it does:
   * Import thunk that forwards to `CompareStringA`.
   */
  int ThunkCompareStringA(
    const LCID locale,
    const DWORD compareFlags,
    LPCSTR first,
    const int firstLength,
    LPCSTR second,
    const int secondLength
  )
  {
    return ::CompareStringA(locale, compareFlags, first, firstLength, second, secondLength);
  }

  /**
   * Address: 0x00B57BC8 (FUN_00B57BC8)
   *
   * What it does:
   * Import thunk that forwards to `CompareStringW`.
   */
  int ThunkCompareStringW(
    const LCID locale,
    const DWORD compareFlags,
    LPCWSTR first,
    const int firstLength,
    LPCWSTR second,
    const int secondLength
  )
  {
    return ::CompareStringW(locale, compareFlags, first, firstLength, second, secondLength);
  }

  /**
   * Address: 0x00B57BCE (FUN_00B57BCE)
   *
   * What it does:
   * Import thunk that forwards to `FreeEnvironmentStringsA`.
   */
  BOOL ThunkFreeEnvironmentStringsA(LPCH environmentBlock)
  {
    return ::FreeEnvironmentStringsA(environmentBlock);
  }

  /**
   * Address: 0x00B57BD4 (FUN_00B57BD4)
   *
   * What it does:
   * Import thunk that forwards to `GetEnvironmentStrings`.
   */
  LPCH ThunkGetEnvironmentStringsA()
  {
    return ::GetEnvironmentStringsA();
  }

  /**
   * Address: 0x00B57BDA (FUN_00B57BDA)
   *
   * What it does:
   * Import thunk that forwards to `FreeEnvironmentStringsW`.
   */
  BOOL ThunkFreeEnvironmentStringsW(LPWCH environmentBlock)
  {
    return ::FreeEnvironmentStringsW(environmentBlock);
  }

  /**
   * Address: 0x00B57BE0 (FUN_00B57BE0)
   *
   * What it does:
   * Import thunk that forwards to `GetEnvironmentStringsW`.
   */
  LPWCH ThunkGetEnvironmentStringsW()
  {
    return ::GetEnvironmentStringsW();
  }

  /**
   * Address: 0x00B57BE6 (FUN_00B57BE6)
   *
   * What it does:
   * Import thunk that forwards to `HeapDestroy`.
   */
  BOOL ThunkHeapDestroy(HANDLE heap)
  {
    return ::HeapDestroy(heap);
  }

  /**
   * Address: 0x00B57BEC (FUN_00B57BEC)
   *
   * What it does:
   * Import thunk that forwards to `HeapCreate`.
   */
  HANDLE ThunkHeapCreate(const DWORD options, const SIZE_T initialSize, const SIZE_T maximumSize)
  {
    return ::HeapCreate(options, initialSize, maximumSize);
  }

  /**
   * Address: 0x00B57BF2 (FUN_00B57BF2)
   *
   * What it does:
   * Import thunk that forwards to `SetStdHandle`.
   */
  BOOL ThunkSetStdHandle(const DWORD standardHandleId, HANDLE handle)
  {
    return ::SetStdHandle(standardHandleId, handle);
  }

  /**
   * Address: 0x00B57BF8 (FUN_00B57BF8)
   *
   * What it does:
   * Import thunk that forwards to `SetEnvironmentVariableA`.
   */
  BOOL ThunkSetEnvironmentVariableA(LPCSTR name, LPCSTR value)
  {
    return ::SetEnvironmentVariableA(name, value);
  }

  /**
   * Address: 0x00B57BFE (FUN_00B57BFE)
   *
   * What it does:
   * Import thunk that forwards to `WriteConsoleA`.
   */
  BOOL ThunkWriteConsoleA(
    HANDLE console,
    const void* buffer,
    const DWORD charsToWrite,
    LPDWORD charsWritten,
    LPVOID reserved
  )
  {
    return ::WriteConsoleA(console, buffer, charsToWrite, charsWritten, reserved);
  }

  /**
   * Address: 0x00B57C04 (FUN_00B57C04)
   *
   * What it does:
   * Import thunk that forwards to `GetConsoleOutputCP`.
   */
  UINT ThunkGetConsoleOutputCP()
  {
    return ::GetConsoleOutputCP();
  }

  /**
   * Address: 0x00B57C0A (FUN_00B57C0A)
   *
   * What it does:
   * Import thunk that forwards to `WriteConsoleW`.
   */
  BOOL ThunkWriteConsoleW(
    HANDLE console,
    const void* buffer,
    const DWORD charsToWrite,
    LPDWORD charsWritten,
    LPVOID reserved
  )
  {
    return ::WriteConsoleW(console, buffer, charsToWrite, charsWritten, reserved);
  }

  /**
   * Address: 0x00B57C10 (FUN_00B57C10)
   *
   * What it does:
   * Import thunk that forwards to `SetEndOfFile`.
   */
  BOOL ThunkSetEndOfFile(HANDLE file)
  {
    return ::SetEndOfFile(file);
  }

  /**
   * Address: 0x00B57C16 (FUN_00B57C16)
   *
   * What it does:
   * Import thunk that forwards to `HeapReAlloc`.
   */
  LPVOID ThunkHeapReAlloc(HANDLE heap, const DWORD flags, LPVOID block, const SIZE_T bytes)
  {
    return ::HeapReAlloc(heap, flags, block, bytes);
  }

  /**
   * Address: 0x00B57C1C (FUN_00B57C1C)
   *
   * What it does:
   * Import thunk that forwards to `InterlockedCompareExchange`.
   */
  LONG ThunkInterlockedCompareExchange(
    volatile LONG* destination,
    const LONG exchange,
    const LONG comparand
  )
  {
    return ::InterlockedCompareExchange(destination, exchange, comparand);
  }

  /**
   * Address: 0x00B57C22 (FUN_00B57C22)
   *
   * What it does:
   * Import thunk that forwards to `CreateSemaphoreA`.
   */
  HANDLE ThunkCreateSemaphoreA(
    LPSECURITY_ATTRIBUTES securityAttributes,
    const LONG initialCount,
    const LONG maximumCount,
    LPCSTR name
  )
  {
    return ::CreateSemaphoreA(securityAttributes, initialCount, maximumCount, name);
  }

  /**
   * Address: 0x00B57C28 (FUN_00B57C28)
   *
   * What it does:
   * Import thunk that forwards to `CreateEventA`.
   */
  HANDLE ThunkCreateEventA(
    LPSECURITY_ATTRIBUTES securityAttributes,
    const BOOL manualReset,
    const BOOL initialState,
    LPCSTR name
  )
  {
    return ::CreateEventA(securityAttributes, manualReset, initialState, name);
  }

  /**
   * Address: 0x00B57B3E (FUN_00B57B3E)
   *
   * What it does:
   * Import thunk that forwards to `FlushFileBuffers`.
   */
  BOOL ThunkFlushFileBuffers(HANDLE file)
  {
    return ::FlushFileBuffers(file);
  }

  /**
   * Address: 0x00B57B44 (FUN_00B57B44)
   *
   * What it does:
   * Import thunk that forwards to `GetStdHandle`.
   */
  HANDLE ThunkGetStdHandle(const DWORD standardHandleId)
  {
    return ::GetStdHandle(standardHandleId);
  }

  /**
   * Address: 0x00B57B4A (FUN_00B57B4A)
   *
   * What it does:
   * Import thunk that forwards to `GetModuleFileNameA`.
   */
  DWORD ThunkGetModuleFileNameA(HMODULE module, LPSTR outPath, const DWORD outPathChars)
  {
    return ::GetModuleFileNameA(module, outPath, outPathChars);
  }

  /**
   * Address: 0x00B57B50 (FUN_00B57B50)
   *
   * What it does:
   * Import thunk that forwards to `FatalAppExitA`.
   */
  void ThunkFatalAppExitA(const UINT action, LPCSTR message)
  {
    ::FatalAppExitA(action, message);
  }

  /**
   * Address: 0x00B57B56 (FUN_00B57B56)
   *
   * What it does:
   * Import thunk that forwards to `GetCPInfo`.
   */
  BOOL ThunkGetCPInfo(const UINT codePage, LPCPINFO cpInfo)
  {
    return ::GetCPInfo(codePage, cpInfo);
  }

  /**
   * Address: 0x00B57B5C (FUN_00B57B5C)
   *
   * What it does:
   * Import thunk that forwards to `GetOEMCP`.
   */
  UINT ThunkGetOEMCP()
  {
    return ::GetOEMCP();
  }

  /**
   * Address: 0x00B57B62 (FUN_00B57B62)
   *
   * What it does:
   * Import thunk that forwards to `IsValidCodePage`.
   */
  BOOL ThunkIsValidCodePage(const UINT codePage)
  {
    return ::IsValidCodePage(codePage);
  }

  /**
   * Address: 0x00B57B68 (FUN_00B57B68)
   *
   * What it does:
   * Import thunk that forwards to `LCMapStringA`.
   */
  int ThunkLCMapStringA(
    const LCID locale,
    const DWORD mapFlags,
    LPCSTR src,
    const int srcLength,
    LPSTR dst,
    const int dstLength
  )
  {
    return ::LCMapStringA(locale, mapFlags, src, srcLength, dst, dstLength);
  }

  /**
   * Address: 0x00B57B6E (FUN_00B57B6E)
   *
   * What it does:
   * Import thunk that forwards to `LCMapStringW`.
   */
  int ThunkLCMapStringW(
    const LCID locale,
    const DWORD mapFlags,
    LPCWSTR src,
    const int srcLength,
    LPWSTR dst,
    const int dstLength
  )
  {
    return ::LCMapStringW(locale, mapFlags, src, srcLength, dst, dstLength);
  }

  /**
   * Address: 0x00B57B74 (FUN_00B57B74)
   *
   * What it does:
   * Import thunk that forwards to `SetConsoleCtrlHandler`.
   */
  BOOL ThunkSetConsoleCtrlHandler(PHANDLER_ROUTINE handler, const BOOL add)
  {
    return ::SetConsoleCtrlHandler(handler, add);
  }

  /**
   * Address: 0x00B57B7A (FUN_00B57B7A)
   *
   * What it does:
   * Import thunk that forwards to `InterlockedExchange`.
   */
  LONG ThunkInterlockedExchange(volatile LONG* destination, const LONG exchange)
  {
    return ::InterlockedExchange(destination, exchange);
  }

  /**
   * Address: 0x00B57B80 (FUN_00B57B80)
   *
   * What it does:
   * Import thunk that forwards to `GetConsoleCP`.
   */
  UINT ThunkGetConsoleCP()
  {
    return ::GetConsoleCP();
  }

  /**
   * Address: 0x00B57B86 (FUN_00B57B86)
   *
   * What it does:
   * Import thunk that forwards to `GetConsoleMode`.
   */
  BOOL ThunkGetConsoleMode(HANDLE console, LPDWORD outMode)
  {
    return ::GetConsoleMode(console, outMode);
  }

  /**
   * Address: 0x00B57B8C (FUN_00B57B8C)
   *
   * What it does:
   * Import thunk that forwards to `SetHandleCount`.
   */
  UINT ThunkSetHandleCount(const UINT count)
  {
    return ::SetHandleCount(count);
  }

  /**
   * Address: 0x00B57B92 (FUN_00B57B92)
   *
   * What it does:
   * Import thunk that forwards to `GetFileType`.
   */
  DWORD ThunkGetFileType(HANDLE file)
  {
    return ::GetFileType(file);
  }

  /**
   * Address: 0x00B57B98 (FUN_00B57B98)
   *
   * What it does:
   * Import thunk that forwards to `SetFilePointer`.
   */
  DWORD ThunkSetFilePointer(HANDLE file, const LONG moveLow, PLONG moveHigh, const DWORD moveMethod)
  {
    return ::SetFilePointer(file, moveLow, moveHigh, moveMethod);
  }

  /**
   * Address: 0x00B57B9E (FUN_00B57B9E)
   *
   * What it does:
   * Import thunk that forwards to `GetFileAttributesA`.
   */
  DWORD ThunkGetFileAttributesA(LPCSTR path)
  {
    return ::GetFileAttributesA(path);
  }

  /**
   * Address: 0x00B57BA4 (FUN_00B57BA4)
   *
   * What it does:
   * Import thunk that forwards to `GetLocaleInfoA`.
   */
  int ThunkGetLocaleInfoA(const LCID locale, const LCTYPE type, LPSTR outText, const int outChars)
  {
    return ::GetLocaleInfoA(locale, type, outText, outChars);
  }

  /**
   * Address: 0x00B57BAA (FUN_00B57BAA)
   *
   * What it does:
   * Import thunk that forwards to `EnumSystemLocalesA`.
   */
  BOOL ThunkEnumSystemLocalesA(LOCALE_ENUMPROCA callback, const DWORD flags)
  {
    return ::EnumSystemLocalesA(callback, flags);
  }

  /**
   * Address: 0x00B57BB0 (FUN_00B57BB0)
   *
   * What it does:
   * Import thunk that forwards to `IsValidLocale`.
   */
  BOOL ThunkIsValidLocale(const LCID locale, const DWORD flags)
  {
    return ::IsValidLocale(locale, flags);
  }

  /**
   * Address: 0x00B57AC6 (FUN_00B57AC6)
   *
   * What it does:
   * Import thunk that forwards to `GetModuleHandleA`.
   */
  HMODULE ThunkGetModuleHandleA(LPCSTR moduleName)
  {
    return ::GetModuleHandleA(moduleName);
  }

  /**
   * Address: 0x00B57ACC (FUN_00B57ACC)
   *
   * What it does:
   * Import thunk that forwards to `ExitProcess`.
   */
  void ThunkExitProcess(const UINT exitCode)
  {
    ::ExitProcess(exitCode);
  }

  /**
   * Address: 0x00B57AD2 (FUN_00B57AD2)
   *
   * What it does:
   * Import thunk that forwards to `FindFirstFileA`.
   */
  HANDLE ThunkFindFirstFileA(LPCSTR fileName, LPWIN32_FIND_DATAA findData)
  {
    return ::FindFirstFileA(fileName, findData);
  }

  /**
   * Address: 0x00B57AD8 (FUN_00B57AD8)
   *
   * What it does:
   * Import thunk that forwards to `FindNextFileA`.
   */
  BOOL ThunkFindNextFileA(HANDLE findHandle, LPWIN32_FIND_DATAA findData)
  {
    return ::FindNextFileA(findHandle, findData);
  }

  /**
   * Address: 0x00B57ADE (FUN_00B57ADE)
   *
   * What it does:
   * Import thunk that forwards to `UnhandledExceptionFilter`.
   */
  LONG ThunkUnhandledExceptionFilter(PEXCEPTION_POINTERS exceptionInfo)
  {
    return ::UnhandledExceptionFilter(exceptionInfo);
  }

  /**
   * Address: 0x00B57AE4 (FUN_00B57AE4)
   *
   * What it does:
   * Import thunk that forwards to `IsDebuggerPresent`.
   */
  BOOL ThunkIsDebuggerPresent()
  {
    return ::IsDebuggerPresent();
  }

  /**
   * Address: 0x00B57AEA (FUN_00B57AEA)
   *
   * What it does:
   * Import thunk that forwards to `GetTimeZoneInformation`.
   */
  DWORD ThunkGetTimeZoneInformation(LPTIME_ZONE_INFORMATION timeZoneInfo)
  {
    return ::GetTimeZoneInformation(timeZoneInfo);
  }

  /**
   * Address: 0x00B57AF0 (FUN_00B57AF0)
   *
   * What it does:
   * Import thunk that forwards to `RtlUnwind`.
   */
  void ThunkRtlUnwind(
    PVOID targetFrame,
    PVOID targetInstructionPointer,
    PEXCEPTION_RECORD exceptionRecord,
    PVOID returnValue
  )
  {
    ::RtlUnwind(targetFrame, targetInstructionPointer, exceptionRecord, returnValue);
  }

  /**
   * Address: 0x00B57AF6 (FUN_00B57AF6)
   *
   * What it does:
   * Import thunk that forwards to `MoveFileA`.
   */
  BOOL ThunkMoveFileA(LPCSTR existingPath, LPCSTR newPath)
  {
    return ::MoveFileA(existingPath, newPath);
  }

  /**
   * Address: 0x00B57AFC (FUN_00B57AFC)
   *
   * What it does:
   * Import thunk that forwards to `GetTimeFormatA`.
   */
  int ThunkGetTimeFormatA(
    const LCID locale,
    const DWORD flags,
    const SYSTEMTIME* time,
    LPCSTR format,
    LPSTR outBuffer,
    const int outChars
  )
  {
    return ::GetTimeFormatA(locale, flags, time, format, outBuffer, outChars);
  }

  /**
   * Address: 0x00B57B02 (FUN_00B57B02)
   *
   * What it does:
   * Import thunk that forwards to `GetDateFormatA`.
   */
  int ThunkGetDateFormatA(
    const LCID locale,
    const DWORD flags,
    const SYSTEMTIME* date,
    LPCSTR format,
    LPSTR outBuffer,
    const int outChars
  )
  {
    return ::GetDateFormatA(locale, flags, date, format, outBuffer, outChars);
  }

  /**
   * Address: 0x00B57B08 (FUN_00B57B08)
   *
   * What it does:
   * Import thunk that forwards to `GetCommandLineA`.
   */
  LPSTR ThunkGetCommandLineA()
  {
    return ::GetCommandLineA();
  }

  /**
   * Address: 0x00B57B0E (FUN_00B57B0E)
   *
   * What it does:
   * Import thunk that forwards to `HeapFree`.
   */
  BOOL ThunkHeapFree(HANDLE heap, const DWORD flags, LPVOID block)
  {
    return ::HeapFree(heap, flags, block);
  }

  /**
   * Address: 0x00B57B14 (FUN_00B57B14)
   *
   * What it does:
   * Import thunk that forwards to `GetVersionExA`.
   */
  BOOL ThunkGetVersionExA(LPOSVERSIONINFOA versionInfo)
  {
#pragma warning(push)
#pragma warning(disable : 4996)
    return ::GetVersionExA(versionInfo);
#pragma warning(pop)
  }

  /**
   * Address: 0x00B57B1A (FUN_00B57B1A)
   *
   * What it does:
   * Import thunk that forwards to `HeapAlloc`.
   */
  LPVOID ThunkHeapAlloc(HANDLE heap, const DWORD flags, const SIZE_T bytes)
  {
    return ::HeapAlloc(heap, flags, bytes);
  }

  /**
   * Address: 0x00B57B20 (FUN_00B57B20)
   *
   * What it does:
   * Import thunk that forwards to `GetProcessHeap`.
   */
  HANDLE ThunkGetProcessHeap()
  {
    return ::GetProcessHeap();
  }

  /**
   * Address: 0x00B57B26 (FUN_00B57B26)
   *
   * What it does:
   * Import thunk that forwards to `GetStartupInfoA`.
   */
  void ThunkGetStartupInfoA(LPSTARTUPINFOA startupInfo)
  {
    ::GetStartupInfoA(startupInfo);
  }

  /**
   * Address: 0x00B57B2C (FUN_00B57B2C)
   *
   * What it does:
   * Import thunk that forwards to `ExitThread`.
   */
  void ThunkExitThread(const DWORD exitCode)
  {
    ::ExitThread(exitCode);
  }

  /**
   * Address: 0x00B57B32 (FUN_00B57B32)
   *
   * What it does:
   * Import thunk that forwards to `RemoveDirectoryW`.
   */
  BOOL ThunkRemoveDirectoryW(LPCWSTR directoryPath)
  {
    return ::RemoveDirectoryW(directoryPath);
  }

  /**
   * Address: 0x00B57B38 (FUN_00B57B38)
   *
   * What it does:
   * Import thunk that forwards to `GetFullPathNameW`.
   */
  DWORD ThunkGetFullPathNameW(
    LPCWSTR fileName,
    const DWORD outChars,
    LPWSTR outPath,
    LPWSTR* outFilePart
  )
  {
    return ::GetFullPathNameW(fileName, outChars, outPath, outFilePart);
  }

  /**
   * Address: 0x00B57A96 (FUN_00B57A96)
   *
   * What it does:
   * Import thunk that forwards to `timeSetEvent`.
   */
  MMRESULT ThunkTimeSetEvent(
    const UINT delayMs,
    const UINT resolutionMs,
    LPTIMECALLBACK callback,
    const DWORD_PTR userData,
    const UINT eventType
  )
  {
    return ::timeSetEvent(delayMs, resolutionMs, callback, userData, eventType);
  }

  /**
   * Address: 0x00B57A9C (FUN_00B57A9C)
   *
   * What it does:
   * Import thunk that forwards to `timeBeginPeriod`.
   */
  MMRESULT ThunkTimeBeginPeriod(const UINT periodMs)
  {
    return ::timeBeginPeriod(periodMs);
  }

  /**
   * Address: 0x00B57AA2 (FUN_00B57AA2)
   *
   * What it does:
   * Import thunk that forwards to `timeEndPeriod`.
   */
  MMRESULT ThunkTimeEndPeriod(const UINT periodMs)
  {
    return ::timeEndPeriod(periodMs);
  }

  /**
   * Address: 0x00B57AA8 (FUN_00B57AA8)
   *
   * What it does:
   * Import thunk that forwards to `timeKillEvent`.
   */
  MMRESULT ThunkTimeKillEvent(const UINT eventId)
  {
    return ::timeKillEvent(eventId);
  }

  /**
   * Address: 0x00B57AAE (FUN_00B57AAE)
   *
   * What it does:
   * Import thunk that forwards to `GetDriveTypeA`.
   */
  UINT ThunkGetDriveTypeA(LPCSTR rootPath)
  {
    return ::GetDriveTypeA(rootPath);
  }

  /**
   * Address: 0x00B57AB4 (FUN_00B57AB4)
   *
   * What it does:
   * Import thunk that forwards to `GetFullPathNameA`.
   */
  DWORD ThunkGetFullPathNameA(
    LPCSTR fileName,
    const DWORD outChars,
    LPSTR outPath,
    LPSTR* outFilePart
  )
  {
    return ::GetFullPathNameA(fileName, outChars, outPath, outFilePart);
  }

  /**
   * Address: 0x00B57ABA (FUN_00B57ABA)
   *
   * What it does:
   * Import thunk that forwards to `GetCurrentDirectoryA`.
   */
  DWORD ThunkGetCurrentDirectoryA(const DWORD outChars, LPSTR outPath)
  {
    return ::GetCurrentDirectoryA(outChars, outPath);
  }

  /**
   * Address: 0x00B57AC0 (FUN_00B57AC0)
   *
   * What it does:
   * Import thunk that forwards to `SetCurrentDirectoryA`.
   */
  BOOL ThunkSetCurrentDirectoryA(LPCSTR path)
  {
    return ::SetCurrentDirectoryA(path);
  }

  /**
   * Address: 0x00B57C2E (FUN_00B57C2E)
   *
   * What it does:
   * Import thunk that forwards to `PulseEvent`.
   */
  BOOL ThunkPulseEvent(HANDLE eventHandle)
  {
    return ::PulseEvent(eventHandle);
  }

  /**
   * Address: 0x00B57C34 (FUN_00B57C34)
   *
   * What it does:
   * Import thunk that forwards to `SetThreadPriorityBoost`.
   */
  BOOL ThunkSetThreadPriorityBoost(HANDLE threadHandle, const BOOL disablePriorityBoost)
  {
    return ::SetThreadPriorityBoost(threadHandle, disablePriorityBoost);
  }

  /**
   * Address: 0x00B57C3A (FUN_00B57C3A)
   *
   * What it does:
   * Import thunk that forwards to `lstrlenA`.
   */
  int ThunkLstrlenA(LPCSTR text)
  {
    return ::lstrlenA(text);
  }

  /**
   * Address: 0x00B57C40 (FUN_00B57C40)
   *
   * What it does:
   * Import thunk that forwards to `GetThreadPriority`.
   */
  int ThunkGetThreadPriority(HANDLE threadHandle)
  {
    return ::GetThreadPriority(threadHandle);
  }

  /**
   * Address: 0x00B57C46 (FUN_00B57C46)
   *
   * What it does:
   * Import thunk that forwards to `DebugBreak`.
   */
  void ThunkDebugBreak()
  {
    ::DebugBreak();
  }

  /**
   * Address: 0x00B2CCD0 (FUN_00B2CCD0)
   *
   * What it does:
   * Import thunk that forwards to `DirectSoundCreate`.
   */
  HRESULT ThunkDirectSoundCreate(LPCGUID deviceGuid, LPDIRECTSOUND* outDirectSound, LPUNKNOWN outerUnknown)
  {
    return ::DirectSoundCreate(deviceGuid, outDirectSound, outerUnknown);
  }

  /**
   * Address: 0x00B2CCD6 (FUN_00B2CCD6)
   *
   * What it does:
   * Import thunk that forwards to `Direct3DCreate9`.
   */
  IDirect3D9* ThunkDirect3DCreate9(const UINT sdkVersion)
  {
    return ::Direct3DCreate9(sdkVersion);
  }
} // namespace moho::runtime
