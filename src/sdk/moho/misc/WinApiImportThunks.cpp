#include <Windows.h>
#include <commctrl.h>
#include <ddeml.h>
#include <d3d9.h>
#include <mmsystem.h>
#include <processenv.h>
#include <dsound.h>
#include <cstdint>

struct hostent;

extern "C" __declspec(dllimport) LPCH WINAPI GetEnvironmentStringsA(void);
extern "C" __declspec(dllimport) unsigned short* WINAPI D3DXFloat32To16Array(
  unsigned short* outValues,
  const float* inValues,
  unsigned int count
);
extern "C" __declspec(dllimport) HRESULT WINAPI D3DXCreateTextureFromFileInMemoryEx(
  void* device,
  const void* sourceData,
  unsigned int sourceBytes,
  unsigned int width,
  unsigned int height,
  unsigned int mipLevels,
  unsigned int usage,
  std::uint32_t format,
  D3DPOOL pool,
  unsigned int filter,
  unsigned int mipFilter,
  std::uint32_t colorKey,
  const void* sourceInfo,
  void* palette,
  void** outTexture
);
extern "C" __declspec(dllimport) HRESULT WINAPI D3DXCreateVolumeTextureFromFileInMemoryEx(
  void* device,
  const void* sourceData,
  unsigned int sourceBytes,
  unsigned int width,
  unsigned int height,
  unsigned int depth,
  unsigned int mipLevels,
  unsigned int usage,
  std::uint32_t format,
  D3DPOOL pool,
  unsigned int filter,
  unsigned int mipFilter,
  std::uint32_t colorKey,
  const void* sourceInfo,
  void* palette,
  void** outTexture
);
extern "C" __declspec(dllimport) HRESULT WINAPI D3DXCreateCubeTextureFromFileInMemoryEx(
  void* device,
  const void* sourceData,
  unsigned int sourceBytes,
  unsigned int edgeLength,
  unsigned int mipLevels,
  unsigned int usage,
  std::uint32_t format,
  D3DPOOL pool,
  unsigned int filter,
  unsigned int mipFilter,
  std::uint32_t colorKey,
  const void* sourceInfo,
  void* palette,
  void** outTexture
);
extern "C" __declspec(dllimport) HRESULT WINAPI D3DXGetImageInfoFromFileInMemory(
  const void* sourceData,
  unsigned int sourceBytes,
  void* outInfo
);
extern "C" __declspec(dllimport) HRESULT WINAPI D3DXCreateTexture(
  void* device,
  unsigned int width,
  unsigned int height,
  unsigned int mipLevels,
  unsigned int usage,
  std::uint32_t format,
  D3DPOOL pool,
  void** outTexture
);
extern "C" __declspec(dllimport) HRESULT WINAPI D3DXLoadSurfaceFromSurface(
  void* destinationSurface,
  const void* destinationPalette,
  const RECT* destinationRect,
  void* sourceSurface,
  const void* sourcePalette,
  const RECT* sourceRect,
  unsigned int filter,
  std::uint32_t colorKey
);
extern "C" __declspec(dllimport) HRESULT WINAPI D3DXSaveSurfaceToFileA(
  const char* destinationFile,
  unsigned int fileFormat,
  void* sourceSurface,
  const void* sourcePalette,
  const RECT* sourceRect
);
extern "C" __declspec(dllimport) HRESULT WINAPI D3DXSaveSurfaceToFileInMemory(
  void** outBuffer,
  unsigned int fileFormat,
  void* sourceSurface,
  const void* sourcePalette,
  const RECT* sourceRect
);
extern "C" __declspec(dllimport) HRESULT WINAPI D3DXCreateBuffer(
  unsigned int sizeBytes,
  void** outBuffer
);
extern "C" __declspec(dllimport) HRESULT WINAPI D3DXSaveTextureToFileA(
  const char* destinationFile,
  unsigned int fileFormat,
  void* sourceTexture,
  const void* sourcePalette
);
extern "C" __declspec(dllimport) BOOL WINAPI SymGetSymFromAddr(
  HANDLE processHandle,
  DWORD address,
  PDWORD displacementOut,
  void* symbolOut
);
extern "C" __declspec(dllimport) DWORD WINAPI SymSetOptions(DWORD options);
extern "C" __declspec(dllimport) BOOL WINAPI StackWalk(
  DWORD machineType,
  HANDLE processHandle,
  HANDLE threadHandle,
  void* stackFrame,
  void* contextRecord,
  void* readMemoryRoutine,
  void* functionTableAccessRoutine,
  void* getModuleBaseRoutine,
  void* translateAddressRoutine
);
extern "C" __declspec(dllimport) void* WINAPI SymFunctionTableAccess(HANDLE processHandle, DWORD baseAddress);
extern "C" __declspec(dllimport) BOOL WINAPI SymCleanup(HANDLE processHandle);
extern "C" __declspec(dllimport) DWORD WINAPI UnDecorateSymbolName(
  PCSTR decoratedName,
  PSTR undecoratedNameOut,
  DWORD maxOutputChars,
  DWORD flags
);
extern "C" __declspec(dllimport) BOOL WINAPI SymInitialize(
  HANDLE processHandle,
  PCSTR searchPath,
  BOOL invadeProcess
);
extern "C" __declspec(dllimport) BOOL WINAPI SymGetLineFromAddr(
  HANDLE processHandle,
  DWORD address,
  PDWORD displacementOut,
  void* lineOut
);
extern "C" __declspec(dllimport) DWORD WINAPI ReportFault(LPEXCEPTION_POINTERS exceptionPointers, DWORD options);
extern "C" __declspec(dllimport) std::uintptr_t __stdcall socket(int af, int type, int protocol);
extern "C" __declspec(dllimport) int __stdcall __WSAFDIsSet(std::uintptr_t socketHandle, void* fdSet);
extern "C" __declspec(dllimport) int __stdcall
select(int nfds, void* readfds, void* writefds, void* exceptfds, const void* timeout);
extern "C" __declspec(dllimport) int __stdcall
ioctlsocket(std::uintptr_t socketHandle, int command, unsigned long* argument);
extern "C" __declspec(dllimport) unsigned short __stdcall htons(unsigned short hostShort);
extern "C" __declspec(dllimport) unsigned short __stdcall ntohs(unsigned short netShort);
extern "C" __declspec(dllimport) int __stdcall bind(std::uintptr_t socketHandle, const void* name, int nameLength);
extern "C" __declspec(dllimport) int __stdcall recvfrom(
  std::uintptr_t socketHandle,
  char* buffer,
  int bufferLength,
  int flags,
  void* fromAddress,
  int* fromAddressLength
);
extern "C" __declspec(dllimport) int __stdcall sendto(
  std::uintptr_t socketHandle,
  const char* buffer,
  int bufferLength,
  int flags,
  const void* toAddress,
  int toAddressLength
);
extern "C" __declspec(dllimport) int __stdcall recv(
  std::uintptr_t socketHandle,
  char* buffer,
  int bufferLength,
  int flags
);
extern "C" __declspec(dllimport) int __stdcall gethostname(char* name, int nameLength);
extern "C" __declspec(dllimport) unsigned long __stdcall inet_addr(const char* textAddress);
extern "C" __declspec(dllimport) int __stdcall WSACleanup(void);
extern "C" __declspec(dllimport) hostent* __stdcall gethostbyaddr(const char* address, int addressLength, int addressType);
extern "C" __declspec(dllimport) hostent* __stdcall gethostbyname(const char* name);
extern "C" __declspec(dllimport) int __stdcall X3DAudioInitialize(int speakerChannelMask, int speedOfSound, int x3dHandle);
extern "C" __declspec(dllimport) int __stdcall
X3DAudioCalculate(int x3dHandle, int listener, int emitter, int flags, int dspSettings);
extern "C" __declspec(dllimport) HRESULT WINAPI D3DXCreateEffect(
  void* device,
  const void* sourceData,
  unsigned int sourceBytes,
  const void* defines,
  void* include,
  DWORD flags,
  void** outEffectPool,
  void** outEffect,
  void** outCompilationErrors
);
extern "C" __declspec(dllimport) HRESULT WINAPI D3DXCreateEffectCompiler(
  const char* sourceData,
  unsigned int sourceBytes,
  const void* defines,
  void* include,
  DWORD flags,
  void** outEffectCompiler,
  void** outParseErrors
);
extern "C" __declspec(dllimport) const char* WINAPI D3DXGetPixelShaderProfile(void* device);
extern "C" __declspec(dllimport) const char* WINAPI D3DXGetVertexShaderProfile(void* device);
extern "C" __declspec(dllimport) void* WINAPI D3DXMatrixMultiply(void* outMatrix, const void* lhs, const void* rhs);
extern "C" __declspec(dllimport) void* WINAPI D3DXMatrixInverse(void* outMatrix, float* outDeterminant, const void* sourceMatrix);
extern "C" __declspec(dllimport) void* WINAPI D3DXMatrixRotationX(void* outMatrix, float angle);
extern "C" __declspec(dllimport) void* WINAPI D3DXMatrixRotationY(void* outMatrix, float angle);
extern "C" __declspec(dllimport) void* WINAPI D3DXMatrixRotationZ(void* outMatrix, float angle);
extern "C" __declspec(dllimport) void* WINAPI D3DXMatrixRotationAxis(void* outMatrix, const void* axisVector, float angle);
extern "C" __declspec(dllimport) void* WINAPI D3DXMatrixRotationQuaternion(void* outMatrix, const void* quaternion);
extern "C" __declspec(dllimport) void* WINAPI D3DXMatrixTranslation(void* outMatrix, float x, float y, float z);
extern "C" __declspec(dllimport) void* WINAPI D3DXMatrixScaling(void* outMatrix, float x, float y, float z);
extern "C" __declspec(dllimport) void* WINAPI
D3DXMatrixLookAtRH(void* outMatrix, const void* eyePosition, const void* lookAtPosition, const void* upDirection);

namespace moho::runtime
{
  /**
   * Address: 0x00A81C5E (FUN_00A81C5E, DdeFreeDataHandle)
   *
   * What it does:
   * Import thunk that forwards to `DdeFreeDataHandle`.
   */
  BOOL ThunkDdeFreeDataHandle(const HDDEDATA dataHandle)
  {
    return ::DdeFreeDataHandle(dataHandle);
  }

  /**
   * Address: 0x00A81C82 (FUN_00A81C82, DdeClientTransaction)
   *
   * What it does:
   * Import thunk that forwards to `DdeClientTransaction`.
   */
  HDDEDATA ThunkDdeClientTransaction(
    LPBYTE data,
    const DWORD dataBytes,
    const HCONV conversation,
    const HSZ itemHandle,
    const UINT format,
    const UINT transactionType,
    const DWORD timeoutMs,
    LPDWORD outResult
  )
  {
    return ::DdeClientTransaction(
      data,
      dataBytes,
      conversation,
      itemHandle,
      format,
      transactionType,
      timeoutMs,
      outResult
    );
  }

  /**
   * Address: 0x00A81C64 (FUN_00A81C64, DdeGetData)
   *
   * What it does:
   * Import thunk that forwards to `DdeGetData`.
   */
  DWORD ThunkDdeGetData(
    const HDDEDATA dataHandle,
    LPBYTE destination,
    const DWORD maxBytes,
    const DWORD offset
  )
  {
    return ::DdeGetData(dataHandle, destination, maxBytes, offset);
  }

  /**
   * Address: 0x00A81C8E (FUN_00A81C8E, DdeNameService)
   *
   * What it does:
   * Import thunk that forwards to `DdeNameService`.
   */
  HDDEDATA ThunkDdeNameService(const DWORD instanceId, const HSZ service, const HSZ reserved, const UINT command)
  {
    return ::DdeNameService(instanceId, service, reserved, command);
  }

  /**
   * Address: 0x00A81C7C (FUN_00A81C7C, DdeDisconnect)
   *
   * What it does:
   * Import thunk that forwards to `DdeDisconnect`.
   */
  BOOL ThunkDdeDisconnect(const HCONV conversation)
  {
    return ::DdeDisconnect(conversation);
  }

  /**
   * Address: 0x00A81C88 (FUN_00A81C88, DdeCreateStringHandleW)
   *
   * What it does:
   * Import thunk that forwards to `DdeCreateStringHandleW`.
   */
  HSZ ThunkDdeCreateStringHandleW(const DWORD instanceId, LPCWSTR text, const int codePage)
  {
    return ::DdeCreateStringHandleW(instanceId, text, codePage);
  }

  /**
   * Address: 0x00A81C94 (FUN_00A81C94, DdeConnect)
   *
   * What it does:
   * Import thunk that forwards to `DdeConnect`.
   */
  HCONV ThunkDdeConnect(
    const DWORD instanceId,
    const HSZ serviceHandle,
    const HSZ topicHandle,
    PCONVCONTEXT conversationContext
  )
  {
    return ::DdeConnect(instanceId, serviceHandle, topicHandle, conversationContext);
  }

  /**
   * Address: 0x00A81C9A (FUN_00A81C9A, DdePostAdvise)
   *
   * What it does:
   * Import thunk that forwards to `DdePostAdvise`.
   */
  BOOL ThunkDdePostAdvise(const DWORD instanceId, const HSZ topicHandle, const HSZ itemHandle)
  {
    return ::DdePostAdvise(instanceId, topicHandle, itemHandle);
  }

  /**
   * Address: 0x00A81C6A (FUN_00A81C6A, DdeCreateDataHandle)
   *
   * What it does:
   * Import thunk that forwards to `DdeCreateDataHandle`.
   */
  HDDEDATA ThunkDdeCreateDataHandle(
    const DWORD instanceId,
    LPBYTE sourceBytes,
    const DWORD sourceByteCount,
    const DWORD sourceOffset,
    const HSZ itemHandle,
    const UINT format,
    const UINT commandFlags
  )
  {
    return ::DdeCreateDataHandle(
      instanceId,
      sourceBytes,
      sourceByteCount,
      sourceOffset,
      itemHandle,
      format,
      commandFlags
    );
  }

  /**
   * Address: 0x00AA489B (FUN_00AA489B, GetCurrentProcessId)
   *
   * What it does:
   * Import thunk that forwards to `GetCurrentProcessId`.
   */
  DWORD ThunkGetCurrentProcessId()
  {
    return ::GetCurrentProcessId();
  }

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

  /**
   * Address: 0x00AC6422 (FUN_00AC6422, socket)
   *
   * What it does:
   * Import thunk that forwards to `socket`.
   */
  std::uintptr_t ThunkSocket(const int af, const int type, const int protocol)
  {
    return ::socket(af, type, protocol);
  }

  /**
   * Address: 0x00AC6416 (FUN_00AC6416, ntohs)
   *
   * What it does:
   * Import thunk that forwards to `ntohs`.
   */
  unsigned short ThunkNtohs(const unsigned short networkShort)
  {
    return ::ntohs(networkShort);
  }

  /**
   * Address: 0x00AC643A (FUN_00AC643A, htons)
   *
   * What it does:
   * Import thunk that forwards to `htons`.
   */
  unsigned short ThunkHtons(const unsigned short hostShort)
  {
    return ::htons(hostShort);
  }

  /**
   * Address: 0x00AC644C (FUN_00AC644C, bind)
   *
   * What it does:
   * Import thunk that forwards to `bind`.
   */
  int ThunkBind(const std::uintptr_t socketHandle, const void* const name, const int nameLength)
  {
    return ::bind(socketHandle, name, nameLength);
  }

  /**
   * Address: 0x00AC6446 (FUN_00AC6446, recvfrom)
   *
   * What it does:
   * Import thunk that forwards to `recvfrom`.
   */
  int ThunkRecvFrom(
    const std::uintptr_t socketHandle,
    char* const buffer,
    const int bufferLength,
    const int flags,
    void* const fromAddress,
    int* const fromAddressLength
  )
  {
    return ::recvfrom(socketHandle, buffer, bufferLength, flags, fromAddress, fromAddressLength);
  }

  /**
   * Address: 0x00AC6452 (FUN_00AC6452, sendto)
   *
   * What it does:
   * Import thunk that forwards to `sendto`.
   */
  int ThunkSendTo(
    const std::uintptr_t socketHandle,
    const char* const buffer,
    const int bufferLength,
    const int flags,
    const void* const toAddress,
    const int toAddressLength
  )
  {
    return ::sendto(socketHandle, buffer, bufferLength, flags, toAddress, toAddressLength);
  }

  /**
   * Address: 0x00AC64BE (FUN_00AC64BE, recv)
   *
   * What it does:
   * Import thunk that forwards to `recv`.
   */
  int ThunkRecv(
    const std::uintptr_t socketHandle,
    char* const buffer,
    const int bufferLength,
    const int flags
  )
  {
    return ::recv(socketHandle, buffer, bufferLength, flags);
  }

  /**
   * Address: 0x00AC64A0 (FUN_00AC64A0, select)
   *
   * What it does:
   * Import thunk that forwards to `select`.
   */
  int ThunkSelect(
    const int nfds,
    void* const readfds,
    void* const writefds,
    void* const exceptfds,
    const void* const timeout
  )
  {
    return ::select(nfds, readfds, writefds, exceptfds, timeout);
  }

  /**
   * Address: 0x00AC64C4 (FUN_00AC64C4, __WSAFDIsSet)
   *
   * What it does:
   * Import thunk that forwards to `__WSAFDIsSet`.
   */
  int ThunkWSAFDIsSet(const std::uintptr_t socketHandle, void* const fdSet)
  {
    return ::__WSAFDIsSet(socketHandle, fdSet);
  }

  /**
   * Address: 0x00AC64DC (FUN_00AC64DC, WSACleanup)
   *
   * What it does:
   * Import thunk that forwards to `WSACleanup`.
   */
  int ThunkWSACleanup()
  {
    return ::WSACleanup();
  }

  /**
   * Address: 0x00AC64D6 (FUN_00AC64D6, gethostname)
   *
   * What it does:
   * Import thunk that forwards to `gethostname`.
   */
  int ThunkGetHostName(char* const name, const int nameLength)
  {
    return ::gethostname(name, nameLength);
  }

  /**
   * Address: 0x00AC64EE (FUN_00AC64EE, inet_addr)
   *
   * What it does:
   * Import thunk that forwards to `inet_addr`.
   */
  unsigned long ThunkInetAddress(const char* const textAddress)
  {
    return ::inet_addr(textAddress);
  }

  /**
   * Address: 0x00AC64E2 (FUN_00AC64E2, gethostbyaddr)
   *
   * What it does:
   * Import thunk that forwards to `gethostbyaddr`.
   */
  hostent* ThunkGetHostByAddress(const char* const address, const int addressLength, const int addressType)
  {
    return ::gethostbyaddr(address, addressLength, addressType);
  }

  /**
   * Address: 0x00AC64E8 (FUN_00AC64E8, gethostbyname)
   *
   * What it does:
   * Import thunk that forwards to `gethostbyname`.
   */
  hostent* ThunkGetHostByName(const char* const name)
  {
    return ::gethostbyname(name);
  }

  /**
   * Address: 0x00AC6470 (FUN_00AC6470, ioctlsocket)
   *
   * What it does:
   * Import thunk that forwards to `ioctlsocket`.
   */
  int ThunkIoctlsocket(const std::uintptr_t socketHandle, const int command, unsigned long* const argument)
  {
    return ::ioctlsocket(socketHandle, command, argument);
  }

  /**
   * Address: 0x00AC6500 (FUN_00AC6500, SymGetSymFromAddr)
   *
   * What it does:
   * Import thunk that forwards to `SymGetSymFromAddr`.
   */
  BOOL ThunkSymGetSymFromAddr(HANDLE processHandle, DWORD address, PDWORD displacementOut, void* symbolOut)
  {
    return ::SymGetSymFromAddr(processHandle, address, displacementOut, symbolOut);
  }

  /**
   * Address: 0x00AC6506 (FUN_00AC6506, SymSetOptions)
   *
   * What it does:
   * Import thunk that forwards to `SymSetOptions`.
   */
  DWORD ThunkSymSetOptions(const DWORD options)
  {
    return ::SymSetOptions(options);
  }

  /**
   * Address: 0x00AC650C (FUN_00AC650C, StackWalk)
   *
   * What it does:
   * Import thunk that forwards to `StackWalk`.
   */
  BOOL ThunkStackWalk(
    const DWORD machineType,
    HANDLE processHandle,
    HANDLE threadHandle,
    void* stackFrame,
    void* contextRecord,
    void* readMemoryRoutine,
    void* functionTableAccessRoutine,
    void* getModuleBaseRoutine,
    void* translateAddressRoutine
  )
  {
    return ::StackWalk(
      machineType,
      processHandle,
      threadHandle,
      stackFrame,
      contextRecord,
      readMemoryRoutine,
      functionTableAccessRoutine,
      getModuleBaseRoutine,
      translateAddressRoutine
    );
  }

  /**
   * Address: 0x00AC6512 (FUN_00AC6512, SymFunctionTableAccess)
   *
   * What it does:
   * Import thunk that forwards to `SymFunctionTableAccess`.
   */
  void* ThunkSymFunctionTableAccess(HANDLE processHandle, const DWORD baseAddress)
  {
    return ::SymFunctionTableAccess(processHandle, baseAddress);
  }

  /**
   * Address: 0x00AC6518 (FUN_00AC6518, SymCleanup)
   *
   * What it does:
   * Import thunk that forwards to `SymCleanup`.
   */
  BOOL ThunkSymCleanup(HANDLE processHandle)
  {
    return ::SymCleanup(processHandle);
  }

  /**
   * Address: 0x00AC651E (FUN_00AC651E, UnDecorateSymbolName)
   *
   * What it does:
   * Import thunk that forwards to `UnDecorateSymbolName`.
   */
  DWORD ThunkUnDecorateSymbolName(
    PCSTR decoratedName,
    PSTR undecoratedNameOut,
    const DWORD maxOutputChars,
    const DWORD flags
  )
  {
    return ::UnDecorateSymbolName(decoratedName, undecoratedNameOut, maxOutputChars, flags);
  }

  /**
   * Address: 0x00AC6524 (FUN_00AC6524, SymInitialize)
   *
   * What it does:
   * Import thunk that forwards to `SymInitialize`.
   */
  BOOL ThunkSymInitialize(HANDLE processHandle, PCSTR searchPath, const BOOL invadeProcess)
  {
    return ::SymInitialize(processHandle, searchPath, invadeProcess);
  }

  /**
   * Address: 0x00AC652A (FUN_00AC652A, SymGetLineFromAddr)
   *
   * What it does:
   * Import thunk that forwards to `SymGetLineFromAddr`.
   */
  BOOL ThunkSymGetLineFromAddr(HANDLE processHandle, DWORD address, PDWORD displacementOut, void* lineOut)
  {
    return ::SymGetLineFromAddr(processHandle, address, displacementOut, lineOut);
  }

  /**
   * Address: 0x00AC6536 (FUN_00AC6536, ReportFault)
   *
   * What it does:
   * Import thunk that forwards to `ReportFault`.
   */
  DWORD ThunkReportFault(LPEXCEPTION_POINTERS exceptionPointers, const DWORD options)
  {
    return ::ReportFault(exceptionPointers, options);
  }

  /**
   * Address: 0x00AC653C (FUN_00AC653C, _X3DAudioInitialize@12 [X3DAudioInitialize])
   *
   * What it does:
   * Import thunk that forwards to `X3DAudioInitialize`.
   */
  int __stdcall ThunkX3DAudioInitialize(const int speakerChannelMask, const int speedOfSound, const int x3dHandle)
  {
    return ::X3DAudioInitialize(speakerChannelMask, speedOfSound, x3dHandle);
  }

  /**
   * Address: 0x00AC6542 (FUN_00AC6542, _X3DAudioCalculate@20 [X3DAudioCalculate])
   *
   * What it does:
   * Import thunk that forwards to `X3DAudioCalculate`.
   */
  int __stdcall
  ThunkX3DAudioCalculate(const int x3dHandle, const int listener, const int emitter, const int flags, const int dspSettings)
  {
    return ::X3DAudioCalculate(x3dHandle, listener, emitter, flags, dspSettings);
  }

  /**
   * Address: 0x00AC6602 (FUN_00AC6602, D3DXCreateEffect)
   *
   * What it does:
   * Import thunk that forwards to `D3DXCreateEffect`.
   */
  HRESULT ThunkD3DXCreateEffect(
    void* const device,
    const void* const sourceData,
    const unsigned int sourceBytes,
    const void* const defines,
    void* const include,
    const DWORD flags,
    void** const outEffectPool,
    void** const outEffect,
    void** const outCompilationErrors
  )
  {
    return ::D3DXCreateEffect(
      device,
      sourceData,
      sourceBytes,
      defines,
      include,
      flags,
      outEffectPool,
      outEffect,
      outCompilationErrors
    );
  }

  /**
   * Address: 0x00AC6608 (FUN_00AC6608, D3DXCreateEffectCompiler)
   *
   * What it does:
   * Import thunk that forwards to `D3DXCreateEffectCompiler`.
   */
  HRESULT ThunkD3DXCreateEffectCompiler(
    const char* const sourceData,
    const unsigned int sourceBytes,
    const void* const defines,
    void* const include,
    const DWORD flags,
    void** const outEffectCompiler,
    void** const outParseErrors
  )
  {
    return ::D3DXCreateEffectCompiler(
      sourceData,
      sourceBytes,
      defines,
      include,
      flags,
      outEffectCompiler,
      outParseErrors
    );
  }

  /**
   * Address: 0x00AC660E (FUN_00AC660E, D3DXGetPixelShaderProfile)
   *
   * What it does:
   * Import thunk that forwards to `D3DXGetPixelShaderProfile`.
   */
  const char* ThunkD3DXGetPixelShaderProfile(void* const device)
  {
    return ::D3DXGetPixelShaderProfile(device);
  }

  /**
   * Address: 0x00AC6614 (FUN_00AC6614, D3DXGetVertexShaderProfile)
   *
   * What it does:
   * Import thunk that forwards to `D3DXGetVertexShaderProfile`.
   */
  const char* ThunkD3DXGetVertexShaderProfile(void* const device)
  {
    return ::D3DXGetVertexShaderProfile(device);
  }

  /**
   * Address: 0x00AC661A (FUN_00AC661A, D3DXMatrixMultiply)
   *
   * What it does:
   * Import thunk that forwards to `D3DXMatrixMultiply`.
   */
  void* ThunkD3DXMatrixMultiply(void* const outMatrix, const void* const lhs, const void* const rhs)
  {
    return ::D3DXMatrixMultiply(outMatrix, lhs, rhs);
  }

  /**
   * Address: 0x00AC6620 (FUN_00AC6620, D3DXMatrixInverse)
   *
   * What it does:
   * Import thunk that forwards to `D3DXMatrixInverse`.
   */
  void* ThunkD3DXMatrixInverse(void* const outMatrix, float* const outDeterminant, const void* const sourceMatrix)
  {
    return ::D3DXMatrixInverse(outMatrix, outDeterminant, sourceMatrix);
  }

  /**
   * Address: 0x00AC6626 (FUN_00AC6626, D3DXMatrixRotationX)
   *
   * What it does:
   * Import thunk that forwards to `D3DXMatrixRotationX`.
   */
  void* ThunkD3DXMatrixRotationX(void* const outMatrix, const float angle)
  {
    return ::D3DXMatrixRotationX(outMatrix, angle);
  }

  /**
   * Address: 0x00AC662C (FUN_00AC662C, D3DXMatrixRotationY)
   *
   * What it does:
   * Import thunk that forwards to `D3DXMatrixRotationY`.
   */
  void* ThunkD3DXMatrixRotationY(void* const outMatrix, const float angle)
  {
    return ::D3DXMatrixRotationY(outMatrix, angle);
  }

  /**
   * Address: 0x00AC6632 (FUN_00AC6632, D3DXMatrixRotationZ)
   *
   * What it does:
   * Import thunk that forwards to `D3DXMatrixRotationZ`.
   */
  void* ThunkD3DXMatrixRotationZ(void* const outMatrix, const float angle)
  {
    return ::D3DXMatrixRotationZ(outMatrix, angle);
  }

  /**
   * Address: 0x00AC6638 (FUN_00AC6638, D3DXMatrixRotationAxis)
   *
   * What it does:
   * Import thunk that forwards to `D3DXMatrixRotationAxis`.
   */
  void* ThunkD3DXMatrixRotationAxis(void* const outMatrix, const void* const axisVector, const float angle)
  {
    return ::D3DXMatrixRotationAxis(outMatrix, axisVector, angle);
  }

  /**
   * Address: 0x00AC663E (FUN_00AC663E, D3DXMatrixRotationQuaternion)
   *
   * What it does:
   * Import thunk that forwards to `D3DXMatrixRotationQuaternion`.
   */
  void* ThunkD3DXMatrixRotationQuaternion(void* const outMatrix, const void* const quaternion)
  {
    return ::D3DXMatrixRotationQuaternion(outMatrix, quaternion);
  }

  /**
   * Address: 0x00AC6644 (FUN_00AC6644, D3DXMatrixTranslation)
   *
   * What it does:
   * Import thunk that forwards to `D3DXMatrixTranslation`.
   */
  void* ThunkD3DXMatrixTranslation(void* const outMatrix, const float x, const float y, const float z)
  {
    return ::D3DXMatrixTranslation(outMatrix, x, y, z);
  }

  /**
   * Address: 0x00AC664A (FUN_00AC664A, D3DXMatrixScaling)
   *
   * What it does:
   * Import thunk that forwards to `D3DXMatrixScaling`.
   */
  void* ThunkD3DXMatrixScaling(void* const outMatrix, const float x, const float y, const float z)
  {
    return ::D3DXMatrixScaling(outMatrix, x, y, z);
  }

  /**
   * Address: 0x00AC6650 (FUN_00AC6650, D3DXMatrixLookAtRH)
   *
   * What it does:
   * Import thunk that forwards to `D3DXMatrixLookAtRH`.
   */
  void* ThunkD3DXMatrixLookAtRH(
    void* const outMatrix,
    const void* const eyePosition,
    const void* const lookAtPosition,
    const void* const upDirection
  )
  {
    return ::D3DXMatrixLookAtRH(outMatrix, eyePosition, lookAtPosition, upDirection);
  }

  /**
   * Address: 0x00AC6548 (FUN_00AC6548, InitCommonControls)
   *
   * What it does:
   * Import thunk that forwards to `InitCommonControls`.
   */
  void ThunkInitCommonControls()
  {
    ::InitCommonControls();
  }

  /**
   * Address: 0x00AC654E (FUN_00AC654E, ImageList_Create)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_Create`.
   */
  HIMAGELIST ThunkImageListCreate(
    const int iconWidth,
    const int iconHeight,
    const UINT flags,
    const int initialCapacity,
    const int growBy
  )
  {
    return ::ImageList_Create(iconWidth, iconHeight, flags, initialCapacity, growBy);
  }

  /**
   * Address: 0x00AC6554 (FUN_00AC6554, ImageList_Destroy)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_Destroy`.
   */
  BOOL ThunkImageListDestroy(HIMAGELIST imageList)
  {
    return ::ImageList_Destroy(imageList);
  }

  /**
   * Address: 0x00AC655A (FUN_00AC655A, ImageList_GetImageCount)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_GetImageCount`.
   */
  int ThunkImageListGetImageCount(HIMAGELIST imageList)
  {
    return ::ImageList_GetImageCount(imageList);
  }

  /**
   * Address: 0x00AC6560 (FUN_00AC6560, ImageList_GetIconSize)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_GetIconSize`.
   */
  BOOL ThunkImageListGetIconSize(HIMAGELIST imageList, int* outWidth, int* outHeight)
  {
    return ::ImageList_GetIconSize(imageList, outWidth, outHeight);
  }

  /**
   * Address: 0x00AC656C (FUN_00AC656C, ImageList_ReplaceIcon)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_ReplaceIcon`.
   */
  int ThunkImageListReplaceIcon(HIMAGELIST imageList, const int index, HICON icon)
  {
    return ::ImageList_ReplaceIcon(imageList, index, icon);
  }

  /**
   * Address: 0x00AC6572 (FUN_00AC6572, ImageList_Remove)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_Remove`.
   */
  BOOL ThunkImageListRemove(HIMAGELIST imageList, const int index)
  {
    return ::ImageList_Remove(imageList, index);
  }

  /**
   * Address: 0x00AC6578 (FUN_00AC6578, ImageList_Draw)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_Draw`.
   */
  BOOL ThunkImageListDraw(
    HIMAGELIST imageList,
    const int imageIndex,
    HDC destinationDc,
    const int x,
    const int y,
    const UINT drawStyle
  )
  {
    return ::ImageList_Draw(imageList, imageIndex, destinationDc, x, y, drawStyle);
  }

  /**
   * Address: 0x00AC657E (FUN_00AC657E, ImageList_SetBkColor)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_SetBkColor`.
   */
  COLORREF ThunkImageListSetBackgroundColor(HIMAGELIST imageList, const COLORREF color)
  {
    return ::ImageList_SetBkColor(imageList, color);
  }

  /**
   * Address: 0x00AC6584 (FUN_00AC6584, ImageList_Add)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_Add`.
   */
  int ThunkImageListAdd(HIMAGELIST imageList, HBITMAP imageBitmap, HBITMAP maskBitmap)
  {
    return ::ImageList_Add(imageList, imageBitmap, maskBitmap);
  }

  /**
   * Address: 0x00AC658A (FUN_00AC658A, ImageList_Replace)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_Replace`.
   */
  BOOL ThunkImageListReplace(HIMAGELIST imageList, const int index, HBITMAP imageBitmap, HBITMAP maskBitmap)
  {
    return ::ImageList_Replace(imageList, index, imageBitmap, maskBitmap);
  }

  /**
   * Address: 0x00AC6590 (FUN_00AC6590, CreateUpDownControl)
   *
   * What it does:
   * Import thunk that forwards to `CreateUpDownControl`.
   */
  HWND ThunkCreateUpDownControl(
    const DWORD style,
    const int x,
    const int y,
    const int width,
    const int height,
    HWND parentWindow,
    const int controlId,
    HINSTANCE instanceHandle,
    HWND buddyWindow,
    const int upperLimit,
    const int lowerLimit,
    const int initialPosition
  )
  {
    return ::CreateUpDownControl(
      style,
      x,
      y,
      width,
      height,
      parentWindow,
      controlId,
      instanceHandle,
      buddyWindow,
      upperLimit,
      lowerLimit,
      initialPosition
    );
  }

  /**
   * Address: 0x00AC6596 (FUN_00AC6596, CreateStatusWindowW)
   *
   * What it does:
   * Import thunk that forwards to `CreateStatusWindowW`.
   */
  HWND ThunkCreateStatusWindowW(const LONG style, LPCWSTR text, HWND parentWindow, const UINT controlId)
  {
    return ::CreateStatusWindowW(style, text, parentWindow, controlId);
  }

  /**
   * Address: 0x00AC659C (FUN_00AC659C, ImageList_SetDragCursorImage)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_SetDragCursorImage`.
   */
  BOOL ThunkImageListSetDragCursorImage(HIMAGELIST imageList, const int dragImageIndex, const int xHotspot, const int yHotspot)
  {
    return ::ImageList_SetDragCursorImage(imageList, dragImageIndex, xHotspot, yHotspot);
  }

  /**
   * Address: 0x00AC65A2 (FUN_00AC65A2, ImageList_BeginDrag)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_BeginDrag`.
   */
  BOOL ThunkImageListBeginDrag(HIMAGELIST imageList, const int dragImageIndex, const int xHotspot, const int yHotspot)
  {
    return ::ImageList_BeginDrag(imageList, dragImageIndex, xHotspot, yHotspot);
  }

  /**
   * Address: 0x00AC65A8 (FUN_00AC65A8, ImageList_EndDrag)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_EndDrag`.
   */
  void ThunkImageListEndDrag()
  {
    ::ImageList_EndDrag();
  }

  /**
   * Address: 0x00AC65AE (FUN_00AC65AE, ImageList_DragMove)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_DragMove`.
   */
  BOOL ThunkImageListDragMove(const int x, const int y)
  {
    return ::ImageList_DragMove(x, y);
  }

  /**
   * Address: 0x00AC65B4 (FUN_00AC65B4, ImageList_DragEnter)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_DragEnter`.
   */
  BOOL ThunkImageListDragEnter(HWND lockWindow, const int x, const int y)
  {
    return ::ImageList_DragEnter(lockWindow, x, y);
  }

  /**
   * Address: 0x00AC65BA (FUN_00AC65BA, ImageList_DragLeave)
   *
   * What it does:
   * Import thunk that forwards to `ImageList_DragLeave`.
   */
  BOOL ThunkImageListDragLeave(HWND lockWindow)
  {
    return ::ImageList_DragLeave(lockWindow);
  }

  /**
   * Address: 0x00AC65C0 (FUN_00AC65C0, D3DXFloat32To16Array)
   *
   * What it does:
   * Import thunk that forwards to `D3DXFloat32To16Array`.
   */
  unsigned short* ThunkD3DXFloat32To16Array(unsigned short* outValues, const float* inValues, const unsigned int count)
  {
    return ::D3DXFloat32To16Array(outValues, inValues, count);
  }

  /**
   * Address: 0x00AC65C6 (FUN_00AC65C6, D3DXCreateTextureFromFileInMemoryEx)
   *
   * What it does:
   * Import thunk that forwards to `D3DXCreateTextureFromFileInMemoryEx`.
   */
  HRESULT ThunkD3DXCreateTextureFromFileInMemoryEx(
    void* const device,
    const void* const sourceData,
    const unsigned int sourceBytes,
    const unsigned int width,
    const unsigned int height,
    const unsigned int mipLevels,
    const unsigned int usage,
    const std::uint32_t format,
    const D3DPOOL pool,
    const unsigned int filter,
    const unsigned int mipFilter,
    const std::uint32_t colorKey,
    const void* const sourceInfo,
    void* const palette,
    void** const outTexture
  )
  {
    return ::D3DXCreateTextureFromFileInMemoryEx(
      device,
      sourceData,
      sourceBytes,
      width,
      height,
      mipLevels,
      usage,
      format,
      pool,
      filter,
      mipFilter,
      colorKey,
      sourceInfo,
      palette,
      outTexture
    );
  }

  /**
   * Address: 0x00AC65CC (FUN_00AC65CC, D3DXCreateVolumeTextureFromFileInMemoryEx)
   *
   * What it does:
   * Import thunk that forwards to `D3DXCreateVolumeTextureFromFileInMemoryEx`.
   */
  HRESULT ThunkD3DXCreateVolumeTextureFromFileInMemoryEx(
    void* const device,
    const void* const sourceData,
    const unsigned int sourceBytes,
    const unsigned int width,
    const unsigned int height,
    const unsigned int depth,
    const unsigned int mipLevels,
    const unsigned int usage,
    const std::uint32_t format,
    const D3DPOOL pool,
    const unsigned int filter,
    const unsigned int mipFilter,
    const std::uint32_t colorKey,
    const void* const sourceInfo,
    void* const palette,
    void** const outTexture
  )
  {
    return ::D3DXCreateVolumeTextureFromFileInMemoryEx(
      device,
      sourceData,
      sourceBytes,
      width,
      height,
      depth,
      mipLevels,
      usage,
      format,
      pool,
      filter,
      mipFilter,
      colorKey,
      sourceInfo,
      palette,
      outTexture
    );
  }

  /**
   * Address: 0x00AC65D2 (FUN_00AC65D2, D3DXCreateCubeTextureFromFileInMemoryEx)
   *
   * What it does:
   * Import thunk that forwards to `D3DXCreateCubeTextureFromFileInMemoryEx`.
   */
  HRESULT ThunkD3DXCreateCubeTextureFromFileInMemoryEx(
    void* const device,
    const void* const sourceData,
    const unsigned int sourceBytes,
    const unsigned int edgeLength,
    const unsigned int mipLevels,
    const unsigned int usage,
    const std::uint32_t format,
    const D3DPOOL pool,
    const unsigned int filter,
    const unsigned int mipFilter,
    const std::uint32_t colorKey,
    const void* const sourceInfo,
    void* const palette,
    void** const outTexture
  )
  {
    return ::D3DXCreateCubeTextureFromFileInMemoryEx(
      device,
      sourceData,
      sourceBytes,
      edgeLength,
      mipLevels,
      usage,
      format,
      pool,
      filter,
      mipFilter,
      colorKey,
      sourceInfo,
      palette,
      outTexture
    );
  }

  /**
   * Address: 0x00AC65D8 (FUN_00AC65D8, D3DXGetImageInfoFromFileInMemory)
   *
   * What it does:
   * Import thunk that forwards to `D3DXGetImageInfoFromFileInMemory`.
   */
  HRESULT ThunkD3DXGetImageInfoFromFileInMemory(
    const void* const sourceData,
    const unsigned int sourceBytes,
    void* const outInfo
  )
  {
    return ::D3DXGetImageInfoFromFileInMemory(sourceData, sourceBytes, outInfo);
  }

  /**
   * Address: 0x00AC65DE (FUN_00AC65DE, D3DXCreateTexture)
   *
   * What it does:
   * Import thunk that forwards to `D3DXCreateTexture`.
   */
  HRESULT ThunkD3DXCreateTexture(
    void* const device,
    const unsigned int width,
    const unsigned int height,
    const unsigned int mipLevels,
    const unsigned int usage,
    const std::uint32_t format,
    const D3DPOOL pool,
    void** const outTexture
  )
  {
    return ::D3DXCreateTexture(device, width, height, mipLevels, usage, format, pool, outTexture);
  }

  /**
   * Address: 0x00AC65E4 (FUN_00AC65E4, D3DXLoadSurfaceFromSurface)
   *
   * What it does:
   * Import thunk that forwards to `D3DXLoadSurfaceFromSurface`.
   */
  HRESULT ThunkD3DXLoadSurfaceFromSurface(
    void* const destinationSurface,
    const void* const destinationPalette,
    const RECT* const destinationRect,
    void* const sourceSurface,
    const void* const sourcePalette,
    const RECT* const sourceRect,
    const unsigned int filter,
    const std::uint32_t colorKey
  )
  {
    return ::D3DXLoadSurfaceFromSurface(
      destinationSurface,
      destinationPalette,
      destinationRect,
      sourceSurface,
      sourcePalette,
      sourceRect,
      filter,
      colorKey
    );
  }

  /**
   * Address: 0x00AC65EA (FUN_00AC65EA, D3DXSaveSurfaceToFileA)
   *
   * What it does:
   * Import thunk that forwards to `D3DXSaveSurfaceToFileA`.
   */
  HRESULT ThunkD3DXSaveSurfaceToFileA(
    const char* const destinationFile,
    const unsigned int fileFormat,
    void* const sourceSurface,
    const void* const sourcePalette,
    const RECT* const sourceRect
  )
  {
    return ::D3DXSaveSurfaceToFileA(destinationFile, fileFormat, sourceSurface, sourcePalette, sourceRect);
  }

  /**
   * Address: 0x00AC65F0 (FUN_00AC65F0, D3DXSaveSurfaceToFileInMemory)
   *
   * What it does:
   * Import thunk that forwards to `D3DXSaveSurfaceToFileInMemory`.
   */
  HRESULT ThunkD3DXSaveSurfaceToFileInMemory(
    void** const outBuffer,
    const unsigned int fileFormat,
    void* const sourceSurface,
    const void* const sourcePalette,
    const RECT* const sourceRect
  )
  {
    return ::D3DXSaveSurfaceToFileInMemory(outBuffer, fileFormat, sourceSurface, sourcePalette, sourceRect);
  }

  /**
   * Address: 0x00AC65F6 (FUN_00AC65F6, D3DXCreateBuffer)
   *
   * What it does:
   * Import thunk that forwards to `D3DXCreateBuffer`.
   */
  HRESULT ThunkD3DXCreateBuffer(const unsigned int sizeBytes, void** const outBuffer)
  {
    return ::D3DXCreateBuffer(sizeBytes, outBuffer);
  }

  /**
   * Address: 0x00AC65FC (FUN_00AC65FC, D3DXSaveTextureToFileA)
   *
   * What it does:
   * Import thunk that forwards to `D3DXSaveTextureToFileA`.
   */
  HRESULT ThunkD3DXSaveTextureToFileA(
    const char* const destinationFile,
    const unsigned int fileFormat,
    void* const sourceTexture,
    const void* const sourcePalette
  )
  {
    return ::D3DXSaveTextureToFileA(destinationFile, fileFormat, sourceTexture, sourcePalette);
  }

  /**
   * Address: 0x009D23F0 (FUN_009D23F0, GetDesktopWindow)
   *
   * What it does:
   * Import thunk that forwards to `GetDesktopWindow`.
   */
  HWND ThunkGetDesktopWindow()
  {
    return ::GetDesktopWindow();
  }
} // namespace moho::runtime
