#include <Windows.h>
#include <ole2.h>
#include <commctrl.h>
#include <ddeml.h>
#include <d3d9.h>
#include <mmsystem.h>
#include <processenv.h>
#include <dsound.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/BoostWrappers.h"

struct hostent;

namespace moho { class CameraImpl; }

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
extern "C" __declspec(dllimport) BOOL __stdcall WSACloseEvent(HANDLE hEvent);
extern "C" __declspec(dllimport) BOOL __stdcall WSAResetEvent(HANDLE hEvent);
extern "C" __declspec(dllimport) int __stdcall WSAEventSelect(std::uintptr_t socketHandle, HANDLE hEventObject, long networkEvents);
extern "C" __declspec(dllimport) unsigned long __stdcall htonl(unsigned long hostLong);
extern "C" __declspec(dllimport) unsigned long __stdcall ntohl(unsigned long netLong);
extern "C" __declspec(dllimport) int __stdcall setsockopt(
  std::uintptr_t socketHandle,
  int level,
  int optionName,
  const char* optionValue,
  int optionLength
);
extern "C" __declspec(dllimport) HANDLE __stdcall WSACreateEvent(void);
extern "C" __declspec(dllimport) int __stdcall getaddrinfo(
  const char* nodeName,
  const char* serviceName,
  const void* hints,
  void** result
);
extern "C" __declspec(dllimport) int __stdcall getnameinfo(
  const void* sockaddr,
  int sockaddrLength,
  char* nodeBuffer,
  DWORD nodeBufferSize,
  char* serviceBuffer,
  DWORD serviceBufferSize,
  int flags
);
extern "C" __declspec(dllimport) void __stdcall freeaddrinfo(void* addrInfo);
extern "C" __declspec(dllimport) int __stdcall getsockname(std::uintptr_t socketHandle, void* name, int* nameLength);
extern "C" __declspec(dllimport) int __stdcall getpeername(std::uintptr_t socketHandle, void* name, int* nameLength);
extern "C" __declspec(dllimport) DWORD __stdcall WSAWaitForMultipleEvents(
  DWORD eventCount,
  const HANDLE* eventHandles,
  BOOL waitAll,
  DWORD timeoutMs,
  BOOL alertable
);
extern "C" __declspec(dllimport) int __cdecl X3DAudioInitialize(int speakerChannelMask, int speedOfSound, int x3dHandle);
extern "C" __declspec(dllimport) int __cdecl
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
  // 2026-04-16 batch: recovered no-op callback slots with no surviving xrefs.
  /**
   * Address: 0x004DD180 (FUN_004DD180, nullsub_835)
   *
   * What it does:
   * Preserves one legacy no-op callback slot with one reserved integer argument.
   */
  void __stdcall LegacyNoOpRuntimeStdCallSlot017(const std::int32_t /*reservedArg0*/)
  {
  }

  /**
   * Address: 0x0052FB20 (FUN_0052FB20, nullsub_1155)
   *
   * What it does:
   * Preserves one legacy no-op callback slot with one reserved integer argument.
   */
  void __stdcall LegacyNoOpRuntimeStdCallSlot131(const std::int32_t /*reservedArg0*/)
  {
  }

  /**
   * Address: 0x00531C50 (FUN_00531C50, nullsub_1178)
   *
   * What it does:
   * Preserves one legacy no-op callback slot with one reserved integer argument.
   */
  void __stdcall LegacyNoOpRuntimeStdCallSlot154(const std::int32_t /*reservedArg0*/)
  {
  }

  /**
   * Address: 0x00687470 (FUN_00687470, nullsub_1772)
   *
   * What it does:
   * Preserves one legacy no-op callback slot with one reserved integer argument.
   */
  void __stdcall LegacyNoOpRuntimeStdCallSlot525(const std::int32_t /*reservedArg0*/)
  {
  }

  /**
   * Address: 0x007D8010 (FUN_007D8010, nullsub_2575)
   *
   * What it does:
   * Preserves one legacy no-op callback slot with one reserved integer argument.
   */
  void __stdcall LegacyNoOpRuntimeStdCallSlot1303(const std::int32_t /*reservedArg0*/)
  {
  }
  /**
   * Address: 0x0087CC60 (FUN_0087CC60, nullsub_3081)
   *
   * What it does:
   * Preserves one legacy no-op callback slot with one reserved integer argument.
   */
  void __stdcall LegacyNoOpRuntimeStdCallSlot1783(const std::int32_t /*reservedArg0*/)
  {
  }
  /**
   * Address: 0x004F3580 (FUN_004F3580)
   *
   * What it does:
   * Preserves one legacy callback slot that returns zero with no side effects.
   */
  char LegacyZeroResultRuntimeSlot1790()
  {
    return 0;
  }
  struct LegacyLeadingThreeDwordRuntimeView
  {
    std::uint32_t lane00 = 0;
    std::uint32_t lane04 = 0;
    std::uint32_t lane08 = 0;
  };
  static_assert(
    offsetof(LegacyLeadingThreeDwordRuntimeView, lane04) == 0x04,
    "LegacyLeadingThreeDwordRuntimeView::lane04 offset must be 0x04"
  );
  static_assert(
    offsetof(LegacyLeadingThreeDwordRuntimeView, lane08) == 0x08,
    "LegacyLeadingThreeDwordRuntimeView::lane08 offset must be 0x08"
  );
  static_assert(sizeof(LegacyLeadingThreeDwordRuntimeView) == 0x0C, "LegacyLeadingThreeDwordRuntimeView size must be 0x0C");

  /**
   * Address: 0x004D7880 (FUN_004D7880)
   *
   * What it does:
   * Stores source `+0x04` dword into one output lane and returns the same
   * output pointer.
   */
  std::uint32_t* LegacyStoreSourceLane04IntoOutLaneRuntimeLeafBatchDelta02(
    std::uint32_t* const outValue,
    const LegacyLeadingThreeDwordRuntimeView* const source
  )
  {
    outValue[0] = source->lane04;
    return outValue;
  }

  /**
   * Address: 0x004D4200 (FUN_004D4200)
   *
   * What it does:
   * Returns zero when range-begin lane is null; otherwise returns signed element
   * count from `(end - begin) / 84`.
   */
  std::int32_t LegacyCountStride84ElementsFromRangeRuntimeLeafBatchDelta01(
    const LegacyLeadingThreeDwordRuntimeView* const range
  )
  {
    const std::int32_t beginAddress = static_cast<std::int32_t>(range->lane04);
    if (beginAddress == 0)
    {
      return beginAddress;
    }

    const std::int32_t endAddress = static_cast<std::int32_t>(range->lane08);
    return (endAddress - beginAddress) / 84;
  }

  /**
   * Address: 0x005CC800 (FUN_005CC800)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with one reserved integer
   * argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1792(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }
  /**
   * Address: 0x00660D90 (FUN_00660D90, nullsub_1713)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with two reserved integer
   * arguments and no side effects.
   */
  void __stdcall LegacyNoOpRuntimeStdCallTwoArgLaneAlpha(
    const std::int32_t /*reservedArg0*/,
    const std::int32_t /*reservedArg1*/
  )
  {
  }
  /**
   * Address: 0x00660DB0 (FUN_00660DB0, nullsub_1714)
   *
   * What it does:
   * Preserves one legacy callback slot with no side effects.
   */
  void LegacyNoOpRuntimeNoArgLaneAlpha()
  {
  }
  /**
   * Address: 0x00660DC0 (FUN_00660DC0, nullsub_1715)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with one reserved integer
   * argument and no side effects.
   */
  void __stdcall LegacyNoOpRuntimeStdCallOneArgLaneAlpha(const std::int32_t /*reservedArg0*/)
  {
  }
  /**
   * Address: 0x00660DD0 (FUN_00660DD0, nullsub_1716)
   *
   * What it does:
   * Preserves one legacy callback slot with no side effects.
   */
  void LegacyNoOpRuntimeNoArgLaneBeta()
  {
  }
  /**
   * Address: 0x00660E00 (FUN_00660E00, nullsub_1717)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with two reserved integer
   * arguments and no side effects.
   */
  void __stdcall LegacyNoOpRuntimeStdCallTwoArgLaneBeta(
    const std::int32_t /*reservedArg0*/,
    const std::int32_t /*reservedArg1*/
  )
  {
  }
  /**
   * Address: 0x00660DA0 (FUN_00660DA0)
   *
   * What it does:
   * Preserves one legacy callback slot that returns zero with no side effects.
   */
  std::int32_t LegacyZeroResultRuntimeSlot1793()
  {
    return 0;
  }
  /**
   * Address: 0x00662570 (FUN_00662570, nullsub_1719)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with one reserved integer
   * argument and no side effects.
   */
  void __stdcall LegacyNoOpRuntimeStdCallOneArgLaneBeta(const std::int32_t /*reservedArg0*/)
  {
  }
  /**
   * Address: 0x007146B0 (FUN_007146B0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with one reserved integer
   * argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1794(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }
  /**
   * Address: 0x00797080 (FUN_00797080)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1799(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x007E6960 (FUN_007E6960)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1800(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x008E8A10 (FUN_008E8A10)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1805(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x008F9010 (FUN_008F9010)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1806(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x008F9070 (FUN_008F9070)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1807(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x008F90A0 (FUN_008F90A0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1808(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x008F90D0 (FUN_008F90D0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1809(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x008F9100 (FUN_008F9100)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1810(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x008F9130 (FUN_008F9130)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1811(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x0094B620 (FUN_0094B620)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1812(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x0094B650 (FUN_0094B650)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1813(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x00967020 (FUN_00967020)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero byte return and no side effects.
   */
  char LegacyZeroResultByteRuntimeSlot1814()
  {
    return 0;
  }

  /**
   * Address: 0x00971080 (FUN_00971080)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 4 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1815(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/, const std::int32_t /*reservedArg3*/)
  {
    return 0;
  }

  /**
   * Address: 0x00971090 (FUN_00971090)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 3 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1816(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/)
  {
    return 0;
  }

  /**
   * Address: 0x009763D0 (FUN_009763D0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 6 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1817(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/, const std::int32_t /*reservedArg3*/, const std::int32_t /*reservedArg4*/, const std::int32_t /*reservedArg5*/)
  {
    return 0;
  }

  /**
   * Address: 0x009763E0 (FUN_009763E0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 5 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1818(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/, const std::int32_t /*reservedArg3*/, const std::int32_t /*reservedArg4*/)
  {
    return 0;
  }

  /**
   * Address: 0x009763F0 (FUN_009763F0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 4 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1819(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/, const std::int32_t /*reservedArg3*/)
  {
    return 0;
  }

  /**
   * Address: 0x0097C8F0 (FUN_0097C8F0)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero byte return and no side effects.
   */
  char LegacyZeroResultByteRuntimeSlot1820()
  {
    return 0;
  }

  /**
   * Address: 0x0097D040 (FUN_0097D040)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero byte return and no side effects.
   */
  char LegacyZeroResultByteRuntimeSlot1821()
  {
    return 0;
  }

  /**
   * Address: 0x0097F9C0 (FUN_0097F9C0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 3 reserved integer arguments and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1822(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/)
  {
    return 0;
  }

  /**
   * Address: 0x00999B80 (FUN_00999B80)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 3 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1824(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/)
  {
    return 0;
  }

  /**
   * Address: 0x0099A0B0 (FUN_0099A0B0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1825(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x0099E760 (FUN_0099E760)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero byte return and no side effects.
   */
  char LegacyZeroResultByteRuntimeSlot1827()
  {
    return 0;
  }

  /**
   * Address: 0x009A8ED0 (FUN_009A8ED0)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero byte return and no side effects.
   */
  char LegacyZeroResultByteRuntimeSlot1828()
  {
    return 0;
  }

  /**
   * Address: 0x009AB390 (FUN_009AB390)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 6 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1829(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/, const std::int32_t /*reservedArg3*/, const std::int32_t /*reservedArg4*/, const std::int32_t /*reservedArg5*/)
  {
    return 0;
  }

  /**
   * Address: 0x009AB3A0 (FUN_009AB3A0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 3 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1830(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/)
  {
    return 0;
  }

  /**
   * Address: 0x009D7FD0 (FUN_009D7FD0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 3 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1831(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/)
  {
    return 0;
  }

  /**
   * Address: 0x009DD2D0 (FUN_009DD2D0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 2 reserved integer arguments and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1832(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/)
  {
    return 0;
  }

  /**
   * Address: 0x009ED880 (FUN_009ED880)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 6 reserved integer arguments and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1833(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/, const std::int32_t /*reservedArg3*/, const std::int32_t /*reservedArg4*/, const std::int32_t /*reservedArg5*/)
  {
    return 0;
  }

  /**
   * Address: 0x009EE4C0 (FUN_009EE4C0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 2 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1834(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/)
  {
    return 0;
  }

  /**
   * Address: 0x009FCD90 (FUN_009FCD90)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero byte return and no side effects.
   */
  char LegacyZeroResultByteRuntimeSlot1835()
  {
    return 0;
  }

  /**
   * Address: 0x00A05C40 (FUN_00A05C40)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero byte return and no side effects.
   */
  char LegacyZeroResultByteRuntimeSlot1836()
  {
    return 0;
  }

  /**
   * Address: 0x00A05D30 (FUN_00A05D30)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero byte return and no side effects.
   */
  char LegacyZeroResultByteRuntimeSlot1837()
  {
    return 0;
  }

  /**
   * Address: 0x00A0E3B0 (FUN_00A0E3B0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1838(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A18DC0 (FUN_00A18DC0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1839(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A191E0 (FUN_00A191E0)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero return and no side effects.
   */
  std::int32_t LegacyZeroResultRuntimeSlot1840()
  {
    return 0;
  }

  /**
   * Address: 0x00A191F0 (FUN_00A191F0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1841(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A19200 (FUN_00A19200)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 2 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1842(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A19460 (FUN_00A19460)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero return and no side effects.
   */
  std::int32_t LegacyZeroResultRuntimeSlot1843()
  {
    return 0;
  }

  /**
   * Address: 0x00A19470 (FUN_00A19470)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1844(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A19520 (FUN_00A19520)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 3 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1845(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A1A2E0 (FUN_00A1A2E0)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero byte return and no side effects.
   */
  char LegacyZeroResultByteRuntimeSlot1846()
  {
    return 0;
  }

  /**
   * Address: 0x00A2D7A0 (FUN_00A2D7A0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1847(const std::int32_t /*reservedArg0*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A30E40 (FUN_00A30E40)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 4 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1848(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/, const std::int32_t /*reservedArg3*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A30E50 (FUN_00A30E50)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 4 reserved integer arguments and a constant zero return.
   */
  std::int32_t __stdcall LegacyZeroResultRuntimeStdCallSlot1849(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/, const std::int32_t /*reservedArg3*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A30E60 (FUN_00A30E60)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 5 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1850(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/, const std::int32_t /*reservedArg3*/, const std::int32_t /*reservedArg4*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A30E70 (FUN_00A30E70)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 2 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1851(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A30E80 (FUN_00A30E80)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 2 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1852(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A30E90 (FUN_00A30E90)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 5 reserved integer arguments and a constant zero return.
   */
  char __stdcall LegacyZeroResultByteRuntimeStdCallSlot1853(const std::int32_t /*reservedArg0*/, const std::int32_t /*reservedArg1*/, const std::int32_t /*reservedArg2*/, const std::int32_t /*reservedArg3*/, const std::int32_t /*reservedArg4*/)
  {
    return 0;
  }

  /**
   * Address: 0x00A37F20 (FUN_00A37F20)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero byte return and no side effects.
   */
  char LegacyZeroResultByteRuntimeSlot1854()
  {
    return 0;
  }

  /**
   * Address: 0x00AB7F00 (FUN_00AB7F00)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero return and no side effects.
   */
  std::int32_t LegacyZeroResultRuntimeSlot1855()
  {
    return 0;
  }

  /**
   * Address: 0x00AC6020 (FUN_00AC6020)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant zero return and no side effects.
   */
  std::int32_t LegacyZeroResultRuntimeSlot1856()
  {
    return 0;
  }


  /**
   * Address: 0x00928EC0 (FUN_00928EC0)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one return and no side effects.
   */
  std::int32_t LegacyOneResultRuntimeSlot48()
  {
    return 1;
  }

  /**
   * Address: 0x009710A0 (FUN_009710A0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant one return.
   */
  std::int32_t __stdcall LegacyOneResultRuntimeStdCallSlot52(const std::int32_t /*reservedArg0*/)
  {
    return 1;
  }

  /**
   * Address: 0x0097F620 (FUN_0097F620)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot53()
  {
    return 1;
  }

  /**
   * Address: 0x00995500 (FUN_00995500)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot54()
  {
    return 1;
  }

  /**
   * Address: 0x009A64D0 (FUN_009A64D0)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one return and no side effects.
   */
  std::int32_t LegacyOneResultRuntimeSlot55()
  {
    return 1;
  }

  /**
   * Address: 0x009BF1F0 (FUN_009BF1F0)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot56()
  {
    return 1;
  }

  /**
   * Address: 0x009C6310 (FUN_009C6310)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot57()
  {
    return 1;
  }

  /**
   * Address: 0x009C6960 (FUN_009C6960)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot58()
  {
    return 1;
  }

  /**
   * Address: 0x009C88D0 (FUN_009C88D0)
   *
   * What it does:
   * Preserves one legacy stdcall callback slot with 1 reserved integer argument and a constant one return.
   */
  char __stdcall LegacyOneResultByteRuntimeStdCallSlot59(const std::int32_t /*reservedArg0*/)
  {
    return 1;
  }

  /**
   * Address: 0x009C8C00 (FUN_009C8C00)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot60()
  {
    return 1;
  }

  /**
   * Address: 0x004E7A90 (FUN_004E7A90)
   *
   * What it does:
   * Preserves one legacy fastcall callback slot that returns the high byte of its packed integer argument.
   */
  char __fastcall LegacyHighByteResultRuntimeFastCallSlot8(const std::int32_t packedValue)
  {
    return HIBYTE(packedValue);
  }

  /**
   * Address: 0x004E7AF0 (FUN_004E7AF0)
   *
   * What it does:
   * Preserves one legacy fastcall callback slot that returns the high byte of its packed integer argument.
   */
  char __fastcall LegacyHighByteResultRuntimeFastCallSlot9(const std::int32_t packedValue)
  {
    return HIBYTE(packedValue);
  }

  /**
   * Address: 0x009CA300 (FUN_009CA300)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot61()
  {
    return 1;
  }

  /**
   * Address: 0x009D58E0 (FUN_009D58E0)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot63()
  {
    return 1;
  }

  using LegacyVirtualIntReader = int(__thiscall*)(void*);

  /**
   * Address: 0x00762EC0 (FUN_00762EC0)
   *
   * What it does:
   * Returns the reflected type-name literal for `HPathCell`.
   */
  const char* LegacyTypeNameLiteralHPathCellRuntimeSlot1()
  {
    return "HPathCell";
  }

  /**
   * Address: 0x007630D0 (FUN_007630D0)
   *
   * What it does:
   * Returns the reflected type-name literal for `NavPath`.
   */
  const char* LegacyTypeNameLiteralNavPathRuntimeSlot1()
  {
    return "NavPath";
  }

  struct LegacySourcePlus652And660DwordRuntimeView
  {
    std::uint32_t reserved00[0xA3] = {};
    std::uint32_t lane28C = 0;
    std::uint32_t reserved290 = 0;
    std::uint32_t lane294 = 0;
  };
  static_assert(
    offsetof(LegacySourcePlus652And660DwordRuntimeView, lane28C) == 0x28C,
    "LegacySourcePlus652And660DwordRuntimeView::lane28C offset must be 0x28C"
  );
  static_assert(
    offsetof(LegacySourcePlus652And660DwordRuntimeView, lane294) == 0x294,
    "LegacySourcePlus652And660DwordRuntimeView::lane294 offset must be 0x294"
  );

  /**
   * Address: 0x00AD9AF0 (FUN_00AD9AF0)
   *
   * What it does:
   * Loads and returns one dword lane from source `+0x28C`.
   */
  std::uint32_t LegacyLoadDwordAtSourcePlus652RuntimeLaneRawSlot1(
    const LegacySourcePlus652And660DwordRuntimeView* const sourceValue
  )
  {
    return sourceValue->lane28C;
  }


  /**
   * Address: 0x009FCDA0 (FUN_009FCDA0)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot65()
  {
    return 1;
  }

  /**
   * Address: 0x00A0DB50 (FUN_00A0DB50)
   *
   * What it does:
   * Clears the process clipboard-object lane by calling `OleSetClipboard`
   * with a null data-object pointer.
   */
  [[maybe_unused]] HRESULT LegacyOleSetClipboardNullRuntimeSlot()
  {
    return ::OleSetClipboard(nullptr);
  }

  /**
   * Address: 0x00A069B0 (FUN_00A069B0)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot66()
  {
    return 1;
  }

  /**
   * Address: 0x00A0DB80 (FUN_00A0DB80)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot67()
  {
    return 1;
  }

  /**
   * Address: 0x00A0DB90 (FUN_00A0DB90)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot68()
  {
    return 1;
  }

  /**
   * Address: 0x00A0E440 (FUN_00A0E440)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot69()
  {
    return 1;
  }

  /**
   * Address: 0x00A11A80 (FUN_00A11A80)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one return and no side effects.
   */
  std::int32_t LegacyOneResultRuntimeSlot56()
  {
    return 1;
  }

  /**
   * Address: 0x00A12960 (FUN_00A12960)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot70()
  {
    return 1;
  }

  /**
   * Address: 0x00A144A0 (FUN_00A144A0)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot71()
  {
    return 1;
  }

  /**
   * Address: 0x00A1A300 (FUN_00A1A300)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot72()
  {
    return 1;
  }

  /**
   * Address: 0x00A2E790 (FUN_00A2E790)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot73()
  {
    return 1;
  }

  /**
   * Address: 0x00A30D20 (FUN_00A30D20)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one byte return and no side effects.
   */
  char LegacyOneResultByteRuntimeSlot74()
  {
    return 1;
  }

  /**
   * Address: 0x00AB12B0 (FUN_00AB12B0)
   *
   * What it does:
   * Preserves one legacy callback slot with a constant one return and no side effects.
   */
  std::int32_t LegacyOneResultRuntimeSlot57()
  {
    return 1;
  }



  /**
   * Address: 0x00705500 (FUN_00705500)
   *
   * What it does:
   * Preserves one legacy fastcall callback slot that returns the high byte of its packed integer argument.
   */
  char __fastcall LegacyHighByteResultRuntimeFastCallSlot222(const std::int32_t packedValue)
  {
    return HIBYTE(packedValue);
  }



  /**
   * Address: 0x0080B740 (FUN_0080B740)
   *
   * What it does:
   * Preserves one legacy fastcall callback slot that returns the high byte of its packed integer argument.
   */
  char __fastcall LegacyHighByteResultRuntimeFastCallSlot346(const std::int32_t packedValue)
  {
    return HIBYTE(packedValue);
  }

  /**
   * Address: 0x0080B7A0 (FUN_0080B7A0)
   *
   * What it does:
   * Preserves one legacy fastcall callback slot that returns the high byte of its packed integer argument.
   */
  char __fastcall LegacyHighByteResultRuntimeFastCallSlot347(const std::int32_t packedValue)
  {
    return HIBYTE(packedValue);
  }

  /**
   * Address: 0x0080B800 (FUN_0080B800)
   *
   * What it does:
   * Preserves one legacy fastcall callback slot that returns the high byte of its packed integer argument.
   */
  char __fastcall LegacyHighByteResultRuntimeFastCallSlot348(const std::int32_t packedValue)
  {
    return HIBYTE(packedValue);
  }

  /**
   * Address: 0x0080B860 (FUN_0080B860)
   *
   * What it does:
   * Preserves one legacy fastcall callback slot that returns the high byte of its packed integer argument.
   */
  char __fastcall LegacyHighByteResultRuntimeFastCallSlot349(const std::int32_t packedValue)
  {
    return HIBYTE(packedValue);
  }

  /**
   * Address: 0x0080B8C0 (FUN_0080B8C0)
   *
   * What it does:
   * Preserves one legacy fastcall callback slot that returns the high byte of its packed integer argument.
   */
  char __fastcall LegacyHighByteResultRuntimeFastCallSlot350(const std::int32_t packedValue)
  {
    return HIBYTE(packedValue);
  }

  /**
   * Address: 0x0080B920 (FUN_0080B920)
   *
   * What it does:
   * Preserves one legacy fastcall callback slot that returns the high byte of its packed integer argument.
   */
  char __fastcall LegacyHighByteResultRuntimeFastCallSlot351(const std::int32_t packedValue)
  {
    return HIBYTE(packedValue);
  }

  /**
   * Address: 0x009C9DD0 (FUN_009C9DD0)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2687()
  {
    return 1;
  }

  /**
   * Address: 0x009D3190 (FUN_009D3190)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2688()
  {
    return 1;
  }

  /**
   * Address: 0x00A027B0 (FUN_00A027B0)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2690()
  {
    return 1;
  }

  /**
   * Address: 0x00A0B400 (FUN_00A0B400)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2692()
  {
    return 1;
  }

  /**
   * Address: 0x00A0E5F0 (FUN_00A0E5F0)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2693()
  {
    return -1;
  }

  /**
   * Address: 0x00A0E600 (FUN_00A0E600)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2694()
  {
    return -1;
  }

  /**
   * Address: 0x00A0FF10 (FUN_00A0FF10)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2695()
  {
    return -1;
  }

  /**
   * Address: 0x00A0FF20 (FUN_00A0FF20)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2696()
  {
    return -1;
  }

  /**
   * Address: 0x00A18AF0 (FUN_00A18AF0)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2697()
  {
    return 1;
  }

  /**
   * Address: 0x00A19220 (FUN_00A19220)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2698()
  {
    return 1;
  }

  /**
   * Address: 0x00A1A2F0 (FUN_00A1A2F0)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2699()
  {
    return 1;
  }

  /**
   * Address: 0x00A1A310 (FUN_00A1A310)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2700()
  {
    return 1;
  }

  /**
   * Address: 0x00A1A320 (FUN_00A1A320)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2701()
  {
    return 1;
  }

  /**
   * Address: 0x00A29640 (FUN_00A29640)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2702()
  {
    return 1;
  }

  /**
   * Address: 0x00A2BE00 (FUN_00A2BE00)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2703()
  {
    return 2;
  }

  /**
   * Address: 0x00A2CDC0 (FUN_00A2CDC0)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2704()
  {
    return -2147221501;
  }

  /**
   * Address: 0x00A2CDD0 (FUN_00A2CDD0)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2705()
  {
    return -2147221501;
  }

  /**
   * Address: 0x00A2CDE0 (FUN_00A2CDE0)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2706()
  {
    return -2147221501;
  }

  /**
   * Address: 0x00A2CE90 (FUN_00A2CE90)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2707()
  {
    return 4;
  }

  /**
   * Address: 0x00A30DD0 (FUN_00A30DD0)
   *
   * What it does:
   * Preserves one legacy callback slot with a fixed integer return value.
   */
  std::int32_t LegacyConstantResultRuntimeSlot2708()
  {
    return 1;
  }

  /**
   * Address: 0x008E8D50 (FUN_008E8D50)
   *
   * What it does:
   * Returns the second least-significant byte from one 32-bit integer lane.
   */
  char LegacyHighByteRuntimeSlot88(int value)
  {
    return static_cast<char>((static_cast<unsigned int>(value) >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0092C780 (FUN_0092C780)
   *
   * What it does:
   * Returns the second least-significant byte from one 32-bit integer lane.
   */
  char LegacyHighByteRuntimeSlot104(int value)
  {
    return static_cast<char>((static_cast<unsigned int>(value) >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x005162C0 (FUN_005162C0)
   *
   * What it does:
   * Returns one 32-bit integer argument unchanged.
   */
  int LegacyIdentityIntRuntimeSlot21(int value)
  {
    return value;
  }

  /**
   * Address: 0x00547D80 (FUN_00547D80)
   *
   * What it does:
   * Returns one 32-bit integer argument unchanged.
   */
  int LegacyIdentityIntRuntimeSlot26(int value)
  {
    return value;
  }

  /**
   * Address: 0x005DCC00 (FUN_005DCC00)
   *
   * What it does:
   * Returns one 32-bit integer argument unchanged.
   */
  int LegacyIdentityIntRuntimeSlot70(int value)
  {
    return value;
  }

  /**
   * Address: 0x005FBFE0 (FUN_005FBFE0)
   *
   * What it does:
   * Returns one 32-bit integer argument unchanged.
   */
  int LegacyIdentityIntRuntimeSlot89(int value)
  {
    return value;
  }

  /**
   * Address: 0x00723E00 (FUN_00723E00)
   *
   * What it does:
   * Returns one 32-bit integer argument unchanged.
   */
  int LegacyIdentityIntRuntimeSlot223(int value)
  {
    return value;
  }

  /**
   * Address: 0x00838E30 (FUN_00838E30)
   *
   * What it does:
   * Returns one 32-bit integer argument unchanged.
   */
  int LegacyIdentityIntRuntimeSlot304(int value)
  {
    return value;
  }

  /**
   * Address: 0x009D7E00 (FUN_009D7E00)
   *
   * What it does:
   * Returns one 32-bit integer argument unchanged.
   */
  int LegacyIdentityIntRuntimeSlot418(int value)
  {
    return value;
  }

  /**
   * Address: 0x009E3084 (FUN_009E3084)
   *
   * What it does:
   * Returns one 32-bit integer argument unchanged.
   */
  int LegacyIdentityIntRuntimeSlot419(int value)
  {
    return value;
  }

  /**
   * Address: 0x009FE370 (FUN_009FE370)
   *
   * What it does:
   * Returns one 32-bit integer argument unchanged.
   */
  int LegacyIdentityIntRuntimeSlot422(int value)
  {
    return value;
  }

  /**
   * Address: 0x009FE380 (FUN_009FE380)
   *
   * What it does:
   * Returns one 32-bit integer argument unchanged.
   */
  int LegacyIdentityIntRuntimeSlot423(int value)
  {
    return value;
  }

  /**
   * Address: 0x00A20840 (FUN_00A20840)
   *
   * What it does:
   * Returns one 32-bit integer argument unchanged.
   */
  int LegacyIdentityIntRuntimeSlot424(int value)
  {
    return value;
  }

  /**
   * Address: 0x007194C0 (FUN_007194C0)
   *
   * What it does:
   * Applies one fixed integer offset to one 32-bit integer argument lane.
   */
  int LegacyOffsetIntRuntimeSlot44(int value)
  {
    return static_cast<int>(static_cast<unsigned int>(value) + 4U);
  }

  /**
   * Address: 0x007848A0 (FUN_007848A0)
   *
   * What it does:
   * Applies one fixed integer offset to one 32-bit integer argument lane.
   */
  int LegacyOffsetIntRuntimeSlot80(int value)
  {
    return static_cast<int>(static_cast<unsigned int>(value) + 332U);
  }

  /**
   * Address: 0x004D78A0 (FUN_004D78A0)
   *
   * What it does:
   * Loads one 32-bit integer value from the caller-provided address lane.
   */
  int LegacyLoadDwordAtAddressRuntimeSlot1(int address)
  {
    const auto rawAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x004DB0B0 (FUN_004DB0B0)
   *
   * What it does:
   * Loads one 32-bit integer value from the caller-provided address lane.
   */
  int LegacyLoadDwordAtAddressRuntimeSlot3(int address)
  {
    const auto rawAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x004DE800 (FUN_004DE800)
   *
   * What it does:
   * Loads one 32-bit integer value from the caller-provided address lane.
   */
  int LegacyLoadDwordAtAddressRuntimeSlot17(int address)
  {
    const auto rawAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00549C00 (FUN_00549C00)
   *
   * What it does:
   * Loads one 32-bit integer value from the caller-provided address lane.
   */
  int LegacyLoadDwordAtAddressRuntimeSlot83(int address)
  {
    const auto rawAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00562200 (FUN_00562200)
   *
   * What it does:
   * Loads one 32-bit integer value from the caller-provided address lane.
   */
  int LegacyLoadDwordAtAddressRuntimeSlot110(int address)
  {
    const auto rawAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x0056C790 (FUN_0056C790)
   *
   * What it does:
   * Loads one 32-bit integer value from the caller-provided address lane.
   */
  int LegacyLoadDwordAtAddressRuntimeSlot130(int address)
  {
    const auto rawAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x005FB900 (FUN_005FB900)
   *
   * What it does:
   * Loads one 32-bit integer value from the caller-provided address lane.
   */
  int LegacyLoadDwordAtAddressRuntimeSlot252(int address)
  {
    const auto rawAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x006DB900 (FUN_006DB900)
   *
   * What it does:
   * Loads one 32-bit integer value from the caller-provided address lane.
   */
  int LegacyLoadDwordAtAddressRuntimeSlot366(int address)
  {
    const auto rawAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x007127B0 (FUN_007127B0)
   *
   * What it does:
   * Loads one 32-bit integer value from the caller-provided address lane.
   */
  int LegacyLoadDwordAtAddressRuntimeSlot415(int address)
  {
    const auto rawAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x0050AC00 (FUN_0050AC00)
   *
   * What it does:
   * Loads one 32-bit integer value from caller-provided address lane plus 4 bytes.
   */
  int LegacyLoadDwordAtAddressPlus4RuntimeSlot9(int address)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    const auto rawAddress = baseAddress + 4U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00855C30 (FUN_00855C30)
   *
   * What it does:
   * Loads one 32-bit integer value from caller-provided address lane plus 4 bytes.
   */
  int LegacyLoadDwordAtAddressPlus4RuntimeSlot103(int address)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    const auto rawAddress = baseAddress + 4U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x009DBD80 (FUN_009DBD80)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 4 bytes.
   */
  int LegacyLoadDwordFromThisPlus4RuntimeSlot35(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 4U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x009DD390 (FUN_009DD390)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 4 bytes.
   */
  int LegacyLoadDwordFromThisPlus4RuntimeSlot36(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 4U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x0096FCB0 (FUN_0096FCB0)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 8 bytes.
   */
  int LegacyLoadDwordFromThisPlus8RuntimeSlot17(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 8U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x009EF490 (FUN_009EF490)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 8 bytes.
   */
  int LegacyLoadDwordFromThisPlus8RuntimeSlot37(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 8U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x009DD400 (FUN_009DD400)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 12 bytes.
   */
  int LegacyLoadDwordFromThisPlus12RuntimeSlot18(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 12U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x009F0E90 (FUN_009F0E90)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 12 bytes.
   */
  int LegacyLoadDwordFromThisPlus12RuntimeSlot19(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 12U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A19920 (FUN_00A19920)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 12 bytes.
   */
  int LegacyLoadDwordFromThisPlus12RuntimeSlot26(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 12U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A6BC60 (FUN_00A6BC60)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 12 bytes.
   */
  int LegacyLoadDwordFromThisPlus12RuntimeSlot33(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 12U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00AB12D3 (FUN_00AB12D3)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 12 bytes.
   */
  int LegacyLoadDwordFromThisPlus12RuntimeSlot37(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 12U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A19740 (FUN_00A19740)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 16 bytes.
   */
  int LegacyLoadDwordFromThisPlus16RuntimeSlot23(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 16U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A19930 (FUN_00A19930)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 16 bytes.
   */
  int LegacyLoadDwordFromThisPlus16RuntimeSlot24(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 16U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A6BC70 (FUN_00A6BC70)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 16 bytes.
   */
  int LegacyLoadDwordFromThisPlus16RuntimeSlot36(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 16U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A6BD30 (FUN_00A6BD30)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 16 bytes.
   */
  int LegacyLoadDwordFromThisPlus16RuntimeSlot37(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 16U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00970000 (FUN_00970000)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 20 bytes.
   */
  int LegacyLoadDwordFromThisPlus20RuntimeSlot3(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 20U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A044E0 (FUN_00A044E0)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 20 bytes.
   */
  int LegacyLoadDwordFromThisPlus20RuntimeSlot10(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 20U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A6BC80 (FUN_00A6BC80)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 20 bytes.
   */
  int LegacyLoadDwordFromThisPlus20RuntimeSlot17(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 20U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A6BD40 (FUN_00A6BD40)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 20 bytes.
   */
  int LegacyLoadDwordFromThisPlus20RuntimeSlot18(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 20U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A6BD50 (FUN_00A6BD50)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 24 bytes.
   */
  int LegacyLoadDwordFromThisPlus24RuntimeSlot12(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 24U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A04730 (FUN_00A04730)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 28 bytes.
   */
  int LegacyLoadDwordFromThisPlus28RuntimeSlot4(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 28U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A0E610 (FUN_00A0E610)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 32 bytes.
   */
  int LegacyLoadDwordFromThisPlus32RuntimeSlot7(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 32U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  /**
   * Address: 0x00A0FEE0 (FUN_00A0FEE0)
   *
   * What it does:
   * Loads one 32-bit integer value from object-address lane plus 32 bytes.
   */
  int LegacyLoadDwordFromThisPlus32RuntimeSlot8(int thisAddress)
  {
    const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(thisAddress));
    const auto rawAddress = baseAddress + 32U;
    return static_cast<int>(*reinterpret_cast<const std::uint32_t*>(rawAddress));
  }

  // Address: 0x007AE630 (FUN_007AE630, sub_7AE630) -- compiler-emitted
  // per-element callback for the `_eh_vector_destructor_iterator`-style
  // walk MSVC generates over `Moho::CameraImpl::mTimeSources[2]`
  // (`CameraTimeSourceRuntime*[2]`, CameraImpl.cpp): reads one owned
  // runtime pointer from the array slot passed as `this` and dispatches
  // the pointed object's own vtable slot `+0x04` (its scalar-deleting
  // destructor) with delete flag `1`. Real xrefs: `push offset sub_7AE630`
  // at 0x007A7A4A/0x00BB01D8 (`CameraImpl::CameraImpl`, ctor + its cold
  // chunk) and 0x007A800D (`CameraImpl::~CameraImpl`), each immediately
  // followed by a call into the compiler's array (con/de)structor-iterator
  // helper (0x00A83FC5 / 0x00A83AAC) with `count=2, elementSize=4`. The
  // recovered `CameraImpl::~CameraImpl` (0x007A7F00) already models this
  // exact operation in typed form -- `for (auto*& source :
  // std::span{runtime->mTimeSources, 2}) { delete source; source =
  // nullptr; }` -- since `CameraTimeSourceRuntime` has a virtual
  // destructor at the identical vtable slot this thunk dispatches through,
  // `delete source` compiles to the same dispatch. No registration site
  // needs the raw generic thunk as its own named function: recovering it
  // behind reinterpret_cast-based `DeleteWithFlagVTableRuntimeView`/
  // `OwnedPointerSlotRuntimeView` runtime-view structs would be exactly
  // the raw vtable-slot magic this project's reconstruction-fidelity
  // contract forbids, and nothing in `src/sdk/**` has a source-level call
  // to it (RULE ONE / no-orphan-helper rule) -- so this address
  // intentionally has no dedicated recovered function here.

  /**
   * Address: 0x005C3BB0 (FUN_005C3BB0)
   *
   * What it does:
   * Loads one 32-bit value at address and adds an index lane scaled by 4 bytes.
   */
  int LegacyLoadDwordAtAddressWithIndexStride4RuntimeSlot10(int address, int index)
  {
    const auto rawAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    const auto laneValue = *reinterpret_cast<const std::uint32_t*>(rawAddress);
    const auto indexContribution = static_cast<std::uint32_t>(index) * 4U;
    return static_cast<int>(laneValue + indexContribution);
  }



  /**
   * Address: 0x007B3600 (FUN_007B3600)
   *
   * What it does:
   * Loads one 32-bit value at address+4 and adds the constant lane offset of 8.
   */
  int LegacyLoadDwordAtAddressPlus4ThenAdd8RuntimeSlot12(int address)
  {
    const auto rawAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address));
    const auto laneValue = *reinterpret_cast<const std::uint32_t*>(rawAddress + 4U);
    return static_cast<int>(laneValue + 8U);
  }

  // NOTE (boost shared_ptr / shared_count migration): a local
  // `LegacySharedOwnerPairRuntimeView{objectLane,ownerLane}` +
  // `LegacyCopySharedOwnerPairRetainedCommon` used to duplicate the raw
  // `boost::shared_ptr<T>` `(px,pi)` copy-retain here -- byte-for-byte the
  // same body as `LegacyContainerFillLanes.cpp`'s (deleted)
  // `CopySharedOwnerPairAndRetain`, both of which are
  // `boost::AssignSharedPairRetainCore` (`gpg/core/utils/BoostWrappers.cpp`).
  // The real type is `boost::SharedCountPair`
  // (`gpg/core/utils/BoostWrappers.h`); the two real per-address bodies below
  // now call `boost::AssignSharedPairRetain` directly.

  using LegacyVirtualForwardTenInt = void(__thiscall*)(void*, int, int, int, int, int, int, int, int, int, int);

  struct LegacyVirtualForwardTenIntSlot40VTable
  {
    void* reserved00_27[10];
    LegacyVirtualForwardTenInt forwardAtSlot40;
  };
  static_assert(
    offsetof(LegacyVirtualForwardTenIntSlot40VTable, forwardAtSlot40) == 0x28,
    "LegacyVirtualForwardTenIntSlot40VTable::forwardAtSlot40 offset must be 0x28"
  );

  struct LegacyVirtualForwardTenIntSlot40RuntimeView
  {
    LegacyVirtualForwardTenIntSlot40VTable* vtable;
  };
  static_assert(
    sizeof(LegacyVirtualForwardTenIntSlot40RuntimeView) == 0x4,
    "LegacyVirtualForwardTenIntSlot40RuntimeView size must be 0x4"
  );

  struct LegacyVirtualForwardTenIntSlot36VTable
  {
    void* reserved00_23[9];
    LegacyVirtualForwardTenInt forwardAtSlot36;
  };
  static_assert(
    offsetof(LegacyVirtualForwardTenIntSlot36VTable, forwardAtSlot36) == 0x24,
    "LegacyVirtualForwardTenIntSlot36VTable::forwardAtSlot36 offset must be 0x24"
  );

  struct LegacyVirtualForwardTenIntSlot36RuntimeView
  {
    LegacyVirtualForwardTenIntSlot36VTable* vtable;
  };
  static_assert(
    sizeof(LegacyVirtualForwardTenIntSlot36RuntimeView) == 0x4,
    "LegacyVirtualForwardTenIntSlot36RuntimeView size must be 0x4"
  );

  struct LegacyVirtualForwardTenIntSlot32VTable
  {
    void* reserved00_1F[8];
    LegacyVirtualForwardTenInt forwardAtSlot32;
  };
  static_assert(
    offsetof(LegacyVirtualForwardTenIntSlot32VTable, forwardAtSlot32) == 0x20,
    "LegacyVirtualForwardTenIntSlot32VTable::forwardAtSlot32 offset must be 0x20"
  );

  struct LegacyVirtualForwardTenIntSlot32RuntimeView
  {
    LegacyVirtualForwardTenIntSlot32VTable* vtable;
  };
  static_assert(
    sizeof(LegacyVirtualForwardTenIntSlot32RuntimeView) == 0x4,
    "LegacyVirtualForwardTenIntSlot32RuntimeView size must be 0x4"
  );

  struct LegacyVirtualForwardTenIntSlot28VTable
  {
    void* reserved00_1B[7];
    LegacyVirtualForwardTenInt forwardAtSlot28;
  };
  static_assert(
    offsetof(LegacyVirtualForwardTenIntSlot28VTable, forwardAtSlot28) == 0x1C,
    "LegacyVirtualForwardTenIntSlot28VTable::forwardAtSlot28 offset must be 0x1C"
  );

  struct LegacyVirtualForwardTenIntSlot28RuntimeView
  {
    LegacyVirtualForwardTenIntSlot28VTable* vtable;
  };
  static_assert(
    sizeof(LegacyVirtualForwardTenIntSlot28RuntimeView) == 0x4,
    "LegacyVirtualForwardTenIntSlot28RuntimeView size must be 0x4"
  );

  struct LegacyVirtualForwardTenIntSlot24VTable
  {
    void* reserved00_17[6];
    LegacyVirtualForwardTenInt forwardAtSlot24;
  };
  static_assert(
    offsetof(LegacyVirtualForwardTenIntSlot24VTable, forwardAtSlot24) == 0x18,
    "LegacyVirtualForwardTenIntSlot24VTable::forwardAtSlot24 offset must be 0x18"
  );

  struct LegacyVirtualForwardTenIntSlot24RuntimeView
  {
    LegacyVirtualForwardTenIntSlot24VTable* vtable;
  };
  static_assert(
    sizeof(LegacyVirtualForwardTenIntSlot24RuntimeView) == 0x4,
    "LegacyVirtualForwardTenIntSlot24RuntimeView size must be 0x4"
  );

  struct LegacyVirtualForwardTenIntSlot20VTable
  {
    void* reserved00_13[5];
    LegacyVirtualForwardTenInt forwardAtSlot20;
  };
  static_assert(
    offsetof(LegacyVirtualForwardTenIntSlot20VTable, forwardAtSlot20) == 0x14,
    "LegacyVirtualForwardTenIntSlot20VTable::forwardAtSlot20 offset must be 0x14"
  );

  struct LegacyVirtualForwardTenIntSlot20RuntimeView
  {
    LegacyVirtualForwardTenIntSlot20VTable* vtable;
  };
  static_assert(
    sizeof(LegacyVirtualForwardTenIntSlot20RuntimeView) == 0x4,
    "LegacyVirtualForwardTenIntSlot20RuntimeView size must be 0x4"
  );

  /**
   * Address: 0x00939430 (FUN_00939430)
   *
   * What it does:
   * Invokes virtual slot +0x28 with ten forwarded integer lanes and returns
   * the first forwarded lane.
   */
  int LegacyInvokeVirtualTenIntForwarderSlot40ReturnFirstRuntimeSlot1(
    LegacyVirtualForwardTenIntSlot40RuntimeView* const owner,
    const int arg0,
    const int arg1,
    const int arg2,
    const int arg3,
    const int arg4,
    const int arg5,
    const int arg6,
    const int arg7,
    const int arg8,
    const int arg9
  )
  {
    owner->vtable->forwardAtSlot40(owner, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
    return arg0;
  }

  /**
   * Address: 0x00939490 (FUN_00939490)
   *
   * What it does:
   * Invokes virtual slot +0x24 with ten forwarded integer lanes and returns
   * the first forwarded lane.
   */
  int LegacyInvokeVirtualTenIntForwarderSlot36ReturnFirstRuntimeSlot1(
    LegacyVirtualForwardTenIntSlot36RuntimeView* const owner,
    const int arg0,
    const int arg1,
    const int arg2,
    const int arg3,
    const int arg4,
    const int arg5,
    const int arg6,
    const int arg7,
    const int arg8,
    const int arg9
  )
  {
    owner->vtable->forwardAtSlot36(owner, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
    return arg0;
  }

  /**
   * Address: 0x009394F0 (FUN_009394F0)
   *
   * What it does:
   * Invokes virtual slot +0x20 with ten forwarded integer lanes and returns
   * the first forwarded lane.
   */
  int LegacyInvokeVirtualTenIntForwarderSlot32ReturnFirstRuntimeSlot1(
    LegacyVirtualForwardTenIntSlot32RuntimeView* const owner,
    const int arg0,
    const int arg1,
    const int arg2,
    const int arg3,
    const int arg4,
    const int arg5,
    const int arg6,
    const int arg7,
    const int arg8,
    const int arg9
  )
  {
    owner->vtable->forwardAtSlot32(owner, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
    return arg0;
  }

  /**
   * Address: 0x00939550 (FUN_00939550)
   *
   * What it does:
   * Invokes virtual slot +0x1C with ten forwarded integer lanes and returns
   * the first forwarded lane.
   */
  int LegacyInvokeVirtualTenIntForwarderSlot28ReturnFirstRuntimeSlot1(
    LegacyVirtualForwardTenIntSlot28RuntimeView* const owner,
    const int arg0,
    const int arg1,
    const int arg2,
    const int arg3,
    const int arg4,
    const int arg5,
    const int arg6,
    const int arg7,
    const int arg8,
    const int arg9
  )
  {
    owner->vtable->forwardAtSlot28(owner, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
    return arg0;
  }

  /**
   * Address: 0x009395B0 (FUN_009395B0)
   *
   * What it does:
   * Invokes virtual slot +0x18 with ten forwarded integer lanes and returns
   * the first forwarded lane.
   */
  int LegacyInvokeVirtualTenIntForwarderSlot24ReturnFirstRuntimeSlot1(
    LegacyVirtualForwardTenIntSlot24RuntimeView* const owner,
    const int arg0,
    const int arg1,
    const int arg2,
    const int arg3,
    const int arg4,
    const int arg5,
    const int arg6,
    const int arg7,
    const int arg8,
    const int arg9
  )
  {
    owner->vtable->forwardAtSlot24(owner, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
    return arg0;
  }

  /**
   * Address: 0x00939610 (FUN_00939610)
   *
   * What it does:
   * Invokes virtual slot +0x14 with ten forwarded integer lanes and returns
   * the first forwarded lane.
   */
  int LegacyInvokeVirtualTenIntForwarderSlot20ReturnFirstRuntimeSlot1(
    LegacyVirtualForwardTenIntSlot20RuntimeView* const owner,
    const int arg0,
    const int arg1,
    const int arg2,
    const int arg3,
    const int arg4,
    const int arg5,
    const int arg6,
    const int arg7,
    const int arg8,
    const int arg9
  )
  {
    owner->vtable->forwardAtSlot20(owner, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
    return arg0;
  }

  struct LegacyAddressPlus48RuntimeView
  {
    std::uint8_t reserved00_2F[0x30];
    std::uint8_t anchorAt30;
  };
  static_assert(
    offsetof(LegacyAddressPlus48RuntimeView, anchorAt30) == 0x30,
    "LegacyAddressPlus48RuntimeView::anchorAt30 offset must be 0x30"
  );

  /**
   * Address: 0x00962F00 (FUN_00962F00)
   *
   * What it does:
   * Returns the address lane at this+48.
   */
  char* LegacyReturnThisPlus48RuntimeSlot2(char* const thisAddress)
  {
    auto* const view = reinterpret_cast<LegacyAddressPlus48RuntimeView*>(thisAddress);
    return reinterpret_cast<char*>(&view->anchorAt30);
  }

  /**
   * Address: 0x00978000 (FUN_00978000)
   *
   * What it does:
   * Clears one 32-bit lane at this+0.
   */
  std::uint32_t* LegacyZeroDwordAtThisRuntimeSlot2(std::uint32_t* const thisValue)
  {
    thisValue[0] = 0U;
    return thisValue;
  }

  struct LegacyDwordAtPlus352RuntimeView
  {
    std::uint8_t reserved00_15F[0x160];
    std::uint32_t dwordAt160 = 0;
  };
  static_assert(
    offsetof(LegacyDwordAtPlus352RuntimeView, dwordAt160) == 0x160,
    "LegacyDwordAtPlus352RuntimeView::dwordAt160 offset must be 0x160"
  );

  /**
   * Address: 0x00993490 (FUN_00993490)
   *
   * What it does:
   * Returns whether the 32-bit lane at this+352 is nonzero.
   */
  BOOL LegacyCheckDwordAtThisPlus352IsNonZeroRuntimeSlot1(const LegacyDwordAtPlus352RuntimeView* const thisValue)
  {
    return (thisValue->dwordAt160 != 0U) ? TRUE : FALSE;
  }

  struct LegacyPrimaryStateRuntimeView;

  using LegacyProducePairAtSlot408Fn = void(__thiscall*)(
    LegacyPrimaryStateRuntimeView* owner,
    int* outFirst,
    int* outSecond
  );

  struct LegacyProducePairSlot408VTable
  {
    std::uint8_t reserved00_197[0x198];
    LegacyProducePairAtSlot408Fn producePairAt198 = nullptr;
  };
  static_assert(
    offsetof(LegacyProducePairSlot408VTable, producePairAt198) == 0x198,
    "LegacyProducePairSlot408VTable::producePairAt198 offset must be 0x198"
  );

  using LegacyDispatchAtSlot416Fn = int(__thiscall*)(
    void* dispatcher,
    int arg0,
    int arg1,
    int value0,
    int value1,
    int mode
  );

  struct LegacyDispatchSlot416VTable
  {
    std::uint8_t reserved00_19F[0x1A0];
    LegacyDispatchAtSlot416Fn dispatchAt1A0 = nullptr;
  };
  static_assert(
    offsetof(LegacyDispatchSlot416VTable, dispatchAt1A0) == 0x1A0,
    "LegacyDispatchSlot416VTable::dispatchAt1A0 offset must be 0x1A0"
  );

  struct LegacyDispatchObjectRuntimeView
  {
    LegacyDispatchSlot416VTable* vtable = nullptr;
  };

  struct LegacyPrimaryStateRuntimeView
  {
    LegacyProducePairSlot408VTable* vtable = nullptr;
    std::uint8_t reserved04_23[0x20];
    std::uint32_t dwordAt24 = 0;
    std::uint32_t dwordAt28 = 0;
    std::uint8_t reserved2C_10B[0xE0];
    std::uint32_t dwordAt10C = 0;
    std::uint8_t reserved110_11B[0xC];
    std::uint32_t dwordAt11C = 0;
    std::uint8_t reserved120_12F[0x10];
    std::uint32_t dwordAt130 = 0;
    std::uint32_t dwordAt134 = 0;
    std::uint8_t reserved138_177[0x40];
    std::uint32_t dispatchObjectAddressAt178 = 0;
    std::uint8_t reserved17C_17F[0x4];
    std::uint32_t dwordAt180 = 0;
  };
  static_assert(
    offsetof(LegacyPrimaryStateRuntimeView, dwordAt24) == 0x24,
    "LegacyPrimaryStateRuntimeView::dwordAt24 offset must be 0x24"
  );
  static_assert(
    offsetof(LegacyPrimaryStateRuntimeView, dwordAt28) == 0x28,
    "LegacyPrimaryStateRuntimeView::dwordAt28 offset must be 0x28"
  );
  static_assert(
    offsetof(LegacyPrimaryStateRuntimeView, dwordAt10C) == 0x10C,
    "LegacyPrimaryStateRuntimeView::dwordAt10C offset must be 0x10C"
  );
  static_assert(
    offsetof(LegacyPrimaryStateRuntimeView, dwordAt11C) == 0x11C,
    "LegacyPrimaryStateRuntimeView::dwordAt11C offset must be 0x11C"
  );
  static_assert(
    offsetof(LegacyPrimaryStateRuntimeView, dwordAt130) == 0x130,
    "LegacyPrimaryStateRuntimeView::dwordAt130 offset must be 0x130"
  );
  static_assert(
    offsetof(LegacyPrimaryStateRuntimeView, dwordAt134) == 0x134,
    "LegacyPrimaryStateRuntimeView::dwordAt134 offset must be 0x134"
  );
  static_assert(
    offsetof(LegacyPrimaryStateRuntimeView, dispatchObjectAddressAt178) == 0x178,
    "LegacyPrimaryStateRuntimeView::dispatchObjectAddressAt178 offset must be 0x178"
  );
  static_assert(
    offsetof(LegacyPrimaryStateRuntimeView, dwordAt180) == 0x180,
    "LegacyPrimaryStateRuntimeView::dwordAt180 offset must be 0x180"
  );

  /**
   * Address: 0x009FBE20 (FUN_009FBE20)
   *
   * What it does:
   * If dispatch object pointer at this+376 exists, obtains a two-int pair via
   * owner virtual slot +408 and forwards it to dispatch-object virtual slot
   * +416 with `(0, 0, pair0, pair1, 3)`.
   */
  int LegacyDispatchRendererCallWithProducedPairRuntimeSlot1(
    LegacyPrimaryStateRuntimeView* const thisValue,
    const int /*unusedArgument*/
  )
  {
    const auto dispatchAddress = thisValue->dispatchObjectAddressAt178;
    if (dispatchAddress == 0U) {
      return 0;
    }

    int pair0 = 0;
    int pair1 = 0;
    thisValue->vtable->producePairAt198(thisValue, &pair0, &pair1);

    auto* const dispatchObject = reinterpret_cast<LegacyDispatchObjectRuntimeView*>(
      static_cast<std::uintptr_t>(dispatchAddress)
    );
    return dispatchObject->vtable->dispatchAt1A0(dispatchObject, 0, 0, pair0, pair1, 3);
  }

  /**
   * Address: 0x0089E530 (FUN_0089E530)
   *
   * What it does:
   * Clears dword at this+0 and returns this.
   */
  std::uint32_t* LegacyZeroDwordAtThisAndReturnThisRuntimeLaneAlpha(std::uint32_t* const thisValue)
  {
    thisValue[0] = 0U;
    return thisValue;
  }

  /**
   * Address: 0x009BEDA0 (FUN_009BEDA0)
   *
   * What it does:
   * Clears dword at this+0 and returns this.
   */
  std::uint32_t* LegacyZeroDwordAtThisAndReturnThisRuntimeLaneBeta(std::uint32_t* const thisValue)
  {
    thisValue[0] = 0U;
    return thisValue;
  }

  /**
   * Address: 0x009A99B0 (FUN_009A99B0)
   *
   * What it does:
   * Clears dword lane at this+316 and byte lane at this+320, then returns 0.
   */
  int LegacyClearThisPlus316AndPlus320RuntimeLaneAlpha(std::uint8_t* const thisValue)
  {
    auto* const slot316 = reinterpret_cast<std::uint32_t*>(thisValue + 316);
    slot316[0] = 0U;
    thisValue[320] = 0U;
    return 0;
  }

  struct LegacyVirtualIntReaderSlot536VTable
  {
    std::uint8_t reserved00[0x218];
    LegacyVirtualIntReader readAtSlot536;
  };
  static_assert(
    offsetof(LegacyVirtualIntReaderSlot536VTable, readAtSlot536) == 0x218,
    "LegacyVirtualIntReaderSlot536VTable::readAtSlot536 offset must be 0x218"
  );

  struct LegacyVirtualIntReaderSlot536RuntimeView
  {
    LegacyVirtualIntReaderSlot536VTable* vtable;
  };
  static_assert(
    sizeof(LegacyVirtualIntReaderSlot536RuntimeView) == 0x4,
    "LegacyVirtualIntReaderSlot536RuntimeView size must be 0x4"
  );

  struct LegacyNestedVirtualIntReaderSlot536OwnerAtThisPlus198RuntimeView
  {
    std::uint8_t reserved00[0x198];
    LegacyVirtualIntReaderSlot536RuntimeView* ownerAtPlus198;
  };
  static_assert(
    offsetof(LegacyNestedVirtualIntReaderSlot536OwnerAtThisPlus198RuntimeView, ownerAtPlus198) == 0x198,
    "LegacyNestedVirtualIntReaderSlot536OwnerAtThisPlus198RuntimeView::ownerAtPlus198 offset must be 0x198"
  );

  using LegacyVirtualIntReaderWithIntArg = int(__thiscall*)(void*, int);

  struct LegacyVirtualIntReaderWithIntArgSlot576VTable
  {
    std::uint8_t reserved00[0x240];
    LegacyVirtualIntReaderWithIntArg readAtSlot576;
  };
  static_assert(
    offsetof(LegacyVirtualIntReaderWithIntArgSlot576VTable, readAtSlot576) == 0x240,
    "LegacyVirtualIntReaderWithIntArgSlot576VTable::readAtSlot576 offset must be 0x240"
  );

  struct LegacyVirtualIntReaderWithIntArgSlot576RuntimeView
  {
    LegacyVirtualIntReaderWithIntArgSlot576VTable* vtable;
  };
  static_assert(
    sizeof(LegacyVirtualIntReaderWithIntArgSlot576RuntimeView) == 0x4,
    "LegacyVirtualIntReaderWithIntArgSlot576RuntimeView size must be 0x4"
  );

  /**
   * Address: 0x009824C0 (FUN_009824C0)
   *
   * What it does:
   * Loads nested owner pointer at `this + 0x198` and tail-dispatches to one
   * int-returning virtual slot at nested `vtable + 0x218`.
   */
  int LegacyInvokeNestedVirtualIntReaderSlot536FromThisPlus198RuntimeLaneAlpha(
    LegacyNestedVirtualIntReaderSlot536OwnerAtThisPlus198RuntimeView* const owner
  )
  {
    LegacyVirtualIntReaderSlot536RuntimeView* const nestedOwner = owner->ownerAtPlus198;
    return nestedOwner->vtable->readAtSlot536(nestedOwner);
  }

  /**
   * Address: 0x0098B770 (FUN_0098B770)
   *
   * What it does:
   * Tail-dispatches to one int-returning virtual slot at `vtable + 0x240`
   * passing constant argument `5101`.
   */
  int LegacyInvokeVirtualIntReaderSlot576WithConst5101RuntimeLaneAlpha(
    LegacyVirtualIntReaderWithIntArgSlot576RuntimeView* const owner,
    const int /*unusedArgument*/
  )
  {
    return owner->vtable->readAtSlot576(owner, 5101);
  }

  // NOTE: FUN_0077EDE0 was previously transcribed here as a generic runtime
  // helper (LegacyIsPointedDwordNonZeroRuntimeLaneAlpha). It is actually the
  // GetCount vtable slot of gpg::RPointerType<moho::CDecalHandle> and is now
  // recovered as a method of that specialization in
  // gpg/core/reflection/Reflection.cpp (one-address-one-function).

  struct LegacyVirtualIntReaderSlot160VTable
  {
    std::uint8_t reserved00[0xA0];
    LegacyVirtualIntReader readAtSlot160;
  };
  static_assert(
    offsetof(LegacyVirtualIntReaderSlot160VTable, readAtSlot160) == 0xA0,
    "LegacyVirtualIntReaderSlot160VTable::readAtSlot160 offset must be 0xA0"
  );

  struct LegacyVirtualIntReaderSlot160RuntimeView
  {
    LegacyVirtualIntReaderSlot160VTable* vtable;
  };
  static_assert(
    sizeof(LegacyVirtualIntReaderSlot160RuntimeView) == 0x4,
    "LegacyVirtualIntReaderSlot160RuntimeView size must be 0x4"
  );

  struct LegacyNestedVirtualIntReaderSlot160OwnerAtThisPlus124RuntimeView
  {
    std::uint8_t reserved00[0x124];
    LegacyVirtualIntReaderSlot160RuntimeView* ownerAtPlus124;
  };
  static_assert(
    offsetof(LegacyNestedVirtualIntReaderSlot160OwnerAtThisPlus124RuntimeView, ownerAtPlus124) == 0x124,
    "LegacyNestedVirtualIntReaderSlot160OwnerAtThisPlus124RuntimeView::ownerAtPlus124 offset must be 0x124"
  );

  /**
   * Address: 0x00981BF0 (FUN_00981BF0)
   *
   * What it does:
   * Loads nested owner pointer at `this + 0x124` and calls one int-returning
   * virtual slot at nested `vtable + 0xA0`.
   */
  int LegacyInvokeNestedVirtualIntReaderSlot160FromThisPlus124RuntimeLaneAlpha(
    LegacyNestedVirtualIntReaderSlot160OwnerAtThisPlus124RuntimeView* const owner,
    const int /*unusedArgument*/
  )
  {
    LegacyVirtualIntReaderSlot160RuntimeView* const nestedOwner = owner->ownerAtPlus124;
    return nestedOwner->vtable->readAtSlot160(nestedOwner);
  }

  using LegacyVirtualCallWithDeleteFlag = int(__thiscall*)(void*, int);
  struct LegacyVirtualCallTableRuntimeView
  {
    LegacyVirtualCallWithDeleteFlag slot00;
    LegacyVirtualCallWithDeleteFlag slot04;
    LegacyVirtualCallWithDeleteFlag slot08;
  };

  struct LegacyVirtualCallableRuntimeView
  {
    LegacyVirtualCallTableRuntimeView* vtable;
  };

  struct LegacyOwnerWithCallableAt0CRuntimeView
  {
    std::uint8_t reserved00[0x0C];
    LegacyVirtualCallableRuntimeView* callableAt0C;
  };
  static_assert(
    offsetof(LegacyOwnerWithCallableAt0CRuntimeView, callableAt0C) == 0x0C,
    "LegacyOwnerWithCallableAt0CRuntimeView::callableAt0C offset must be 0x0C"
  );

  [[nodiscard]] int LegacyInvokeCallableSlot0WithDeleteFlagRuntimeLane(
    LegacyOwnerWithCallableAt0CRuntimeView* const owner
  )
  {
    LegacyVirtualCallableRuntimeView* const callable = owner->callableAt0C;
    if (callable == nullptr) {
      return 0;
    }
    return callable->vtable->slot00(callable, 1);
  }

  [[nodiscard]] int LegacyInvokeCallableSlot8WithDeleteFlagRuntimeLane(
    LegacyOwnerWithCallableAt0CRuntimeView* const owner
  )
  {
    LegacyVirtualCallableRuntimeView* const callable = owner->callableAt0C;
    if (callable == nullptr) {
      return 0;
    }
    return callable->vtable->slot08(callable, 1);
  }

  /**
   * Address: 0x00797060 (FUN_00797060)
   *
   * What it does:
   * Invokes callable vtable slot +0x08 at owner+0x0C with delete flag `1`
   * when callable is present.
   */
  int LegacyInvokeCallableSlot8WithDeleteFlagFromThisPlus0CRuntimeLaneAlpha(
    LegacyOwnerWithCallableAt0CRuntimeView* const owner
  )
  {
    return LegacyInvokeCallableSlot8WithDeleteFlagRuntimeLane(owner);
  }

  /**
   * Address: 0x008F9F50 (FUN_008F9F50)
   *
   * What it does:
   * Invokes callable vtable slot +0x00 at owner+0x0C with delete flag `1`
   * when callable is present.
   */
  int LegacyInvokeCallableSlot0WithDeleteFlagFromThisPlus0CRuntimeSlot1(
    LegacyOwnerWithCallableAt0CRuntimeView* const owner
  )
  {
    return LegacyInvokeCallableSlot0WithDeleteFlagRuntimeLane(owner);
  }

  /**
   * Address: 0x008F9F70 (FUN_008F9F70)
   *
   * What it does:
   * Invokes callable vtable slot +0x00 at owner+0x0C with delete flag `1`
   * when callable is present.
   */
  int LegacyInvokeCallableSlot0WithDeleteFlagFromThisPlus0CRuntimeSlot2(
    LegacyOwnerWithCallableAt0CRuntimeView* const owner
  )
  {
    return LegacyInvokeCallableSlot0WithDeleteFlagRuntimeLane(owner);
  }

  /**
   * Address: 0x008F9F80 (FUN_008F9F80)
   *
   * What it does:
   * Invokes callable vtable slot +0x00 at owner+0x0C with delete flag `1`
   * when callable is present.
   */
  int LegacyInvokeCallableSlot0WithDeleteFlagFromThisPlus0CRuntimeSlot3(
    LegacyOwnerWithCallableAt0CRuntimeView* const owner
  )
  {
    return LegacyInvokeCallableSlot0WithDeleteFlagRuntimeLane(owner);
  }

  /**
   * Address: 0x008F9F90 (FUN_008F9F90)
   *
   * What it does:
   * Invokes callable vtable slot +0x00 at owner+0x0C with delete flag `1`
   * when callable is present.
   */
  int LegacyInvokeCallableSlot0WithDeleteFlagFromThisPlus0CRuntimeSlot4(
    LegacyOwnerWithCallableAt0CRuntimeView* const owner
  )
  {
    return LegacyInvokeCallableSlot0WithDeleteFlagRuntimeLane(owner);
  }

  /**
   * Address: 0x008F9FA0 (FUN_008F9FA0)
   *
   * What it does:
   * Invokes callable vtable slot +0x00 at owner+0x0C with delete flag `1`
   * when callable is present.
   */
  int LegacyInvokeCallableSlot0WithDeleteFlagFromThisPlus0CRuntimeSlot5(
    LegacyOwnerWithCallableAt0CRuntimeView* const owner
  )
  {
    return LegacyInvokeCallableSlot0WithDeleteFlagRuntimeLane(owner);
  }

  struct LegacyVirtualStride16CallableRuntimeView
  {
    LegacyVirtualCallTableRuntimeView* vtable = nullptr;
    std::uint8_t reserved04_0F[0x0C] = {};
  };
  static_assert(sizeof(LegacyVirtualStride16CallableRuntimeView) == 0x10, "LegacyVirtualStride16CallableRuntimeView size must be 0x10");

  /**
   * Address: 0x00510980 (FUN_00510980)
   *
   * What it does:
   * Iterates one stride-0x10 callable range and invokes vtable slot +0x08 with
   * argument `0` for each entry, returning the final call result (or begin
   * address when range is empty).
   */
  int LegacyInvokeVirtualSlot8AcrossStride16RangeRuntimeLaneAlpha(
    LegacyVirtualStride16CallableRuntimeView* const beginEntry,
    LegacyVirtualStride16CallableRuntimeView* const endEntry
  )
  {
    auto currentAddress = reinterpret_cast<std::uintptr_t>(beginEntry);
    const auto endAddress = reinterpret_cast<std::uintptr_t>(endEntry);
    int result = static_cast<int>(currentAddress);
    while (currentAddress != endAddress)
    {
      auto* const entry = reinterpret_cast<LegacyVirtualStride16CallableRuntimeView*>(currentAddress);
      result = entry->vtable->slot08(entry, 0);
      currentAddress += sizeof(LegacyVirtualStride16CallableRuntimeView);
    }
    return result;
  }

  struct LegacyTwoDwordPairRuntimeView
  {
    std::uint32_t lane00 = 0U;
    std::uint32_t lane04 = 0U;
  };
  static_assert(sizeof(LegacyTwoDwordPairRuntimeView) == 0x08, "LegacyTwoDwordPairRuntimeView size must be 0x08");

  [[nodiscard]] LegacyTwoDwordPairRuntimeView* LegacyCopyTwoDwordPairRangeWithOutAddressAdvanceRuntimeLane(
    LegacyTwoDwordPairRuntimeView* outValue,
    const LegacyTwoDwordPairRuntimeView* const endValue,
    const LegacyTwoDwordPairRuntimeView* beginValue
  )
  {
    auto outAddress = reinterpret_cast<std::uintptr_t>(outValue);
    while (beginValue != endValue)
    {
      if (outAddress != 0U)
      {
        auto* const outPair = reinterpret_cast<LegacyTwoDwordPairRuntimeView*>(outAddress);
        outPair->lane00 = beginValue->lane00;
        outPair->lane04 = beginValue->lane04;
      }
      ++beginValue;
      outAddress += sizeof(LegacyTwoDwordPairRuntimeView);
    }
    return reinterpret_cast<LegacyTwoDwordPairRuntimeView*>(outAddress);
  }

  [[nodiscard]] LegacyTwoDwordPairRuntimeView* LegacyCopyFixedTwoDwordPairForCountWithOutAddressAdvanceRuntimeLane(
    LegacyTwoDwordPairRuntimeView* outValue,
    const LegacyTwoDwordPairRuntimeView* const sourceValue,
    std::uint32_t count
  )
  {
    auto outAddress = reinterpret_cast<std::uintptr_t>(outValue);
    while (count != 0U)
    {
      if (outAddress != 0U)
      {
        auto* const outPair = reinterpret_cast<LegacyTwoDwordPairRuntimeView*>(outAddress);
        outPair->lane00 = sourceValue->lane00;
        outPair->lane04 = sourceValue->lane04;
      }
      --count;
      outAddress += sizeof(LegacyTwoDwordPairRuntimeView);
    }
    return reinterpret_cast<LegacyTwoDwordPairRuntimeView*>(outAddress);
  }

  /**
   * Address: 0x00541250 (FUN_00541250)
   *
   * What it does:
   * Copies two-dword pairs from begin..end into out, advances out by one pair
   * per iteration regardless of null, and returns final out lane.
   */
  LegacyTwoDwordPairRuntimeView* LegacyCopyTwoDwordPairRangeIntoOutRuntimeSlot1(
    LegacyTwoDwordPairRuntimeView* const outValue,
    const LegacyTwoDwordPairRuntimeView* const endValue,
    const LegacyTwoDwordPairRuntimeView* const beginValue
  )
  {
    return LegacyCopyTwoDwordPairRangeWithOutAddressAdvanceRuntimeLane(
      outValue,
      endValue,
      beginValue
    );
  }

  /**
   * Address: 0x00540BD0 (FUN_00540BD0)
   * Address: 0x00540F60 (FUN_00540F60)
   * Address: 0x005410C0 (FUN_005410C0)
   *
   * What it does:
   * Register-shape adapter that forwards one source-first two-dword range-copy
   * lane into `LegacyCopyTwoDwordPairRangeIntoOutRuntimeSlot1`.
   */
  [[maybe_unused]] LegacyTwoDwordPairRuntimeView* LegacyCopyTwoDwordPairRangeIntoOutRuntimeSlot1RegisterAdapter(
    const LegacyTwoDwordPairRuntimeView* const beginValue,
    const LegacyTwoDwordPairRuntimeView* const endValue,
    LegacyTwoDwordPairRuntimeView* const outValue
  )
  {
    return LegacyCopyTwoDwordPairRangeIntoOutRuntimeSlot1(
      outValue,
      endValue,
      beginValue
    );
  }

  /**
   * Address: 0x0054FF00 (FUN_0054FF00)
   *
   * What it does:
   * Copies two-dword pairs from begin..end into out, advances out by one pair
   * per iteration regardless of null, and returns final out lane.
   */
  LegacyTwoDwordPairRuntimeView* LegacyCopyTwoDwordPairRangeIntoOutRuntimeSlot2(
    LegacyTwoDwordPairRuntimeView* const outValue,
    const LegacyTwoDwordPairRuntimeView* const endValue,
    const LegacyTwoDwordPairRuntimeView* const beginValue
  )
  {
    return LegacyCopyTwoDwordPairRangeWithOutAddressAdvanceRuntimeLane(
      outValue,
      endValue,
      beginValue
    );
  }

  /**
   * Address: 0x00540E80 (FUN_00540E80)
   *
   * What it does:
   * Repeats one fixed two-dword source pair into out for `count` iterations,
   * advancing out by one pair per iteration regardless of null, and returns
   * final out lane.
   */
  LegacyTwoDwordPairRuntimeView* LegacyRepeatFixedTwoDwordPairIntoOutRuntimeSlot1(
    LegacyTwoDwordPairRuntimeView* const outValue,
    const LegacyTwoDwordPairRuntimeView* const sourceValue,
    const std::uint32_t count
  )
  {
    return LegacyCopyFixedTwoDwordPairForCountWithOutAddressAdvanceRuntimeLane(
      outValue,
      sourceValue,
      count
    );
  }

  /**
   * Address: 0x006D2730 (FUN_006D2730)
   *
   * What it does:
   * Repeats one fixed two-dword source pair into out for `count` iterations,
   * advancing out by one pair per iteration regardless of null, and returns
   * final out lane.
   */
  LegacyTwoDwordPairRuntimeView* LegacyRepeatFixedTwoDwordPairIntoOutRuntimeSlot2(
    LegacyTwoDwordPairRuntimeView* const outValue,
    const LegacyTwoDwordPairRuntimeView* const sourceValue,
    const std::uint32_t count
  )
  {
    return LegacyCopyFixedTwoDwordPairForCountWithOutAddressAdvanceRuntimeLane(
      outValue,
      sourceValue,
      count
    );
  }

  /**
   * Address: 0x00733C40 (FUN_00733C40)
   *
   * What it does:
   * Repeats one fixed two-dword source pair into out for `count` iterations,
   * advancing out by one pair per iteration regardless of null, and returns
   * final out lane.
   */
  LegacyTwoDwordPairRuntimeView* LegacyRepeatFixedTwoDwordPairIntoOutRuntimeSlot3(
    LegacyTwoDwordPairRuntimeView* const outValue,
    const LegacyTwoDwordPairRuntimeView* const sourceValue,
    const std::uint32_t count
  )
  {
    return LegacyCopyFixedTwoDwordPairForCountWithOutAddressAdvanceRuntimeLane(
      outValue,
      sourceValue,
      count
    );
  }

  /**
   * Address: 0x00ADC7F0 (FUN_00ADC7F0)
   *
   * What it does:
   * Clears three dword lanes at output and returns output.
   */
  std::uint32_t* LegacyClearThreeDwordLanesAtOutputRuntimeLaneAlpha(std::uint32_t* const outValue)
  {
    outValue[0] = 0U;
    outValue[1] = 0U;
    outValue[2] = 0U;
    return outValue;
  }

  /**
   * Address: 0x00963C90 (FUN_00963C90)
   *
   * What it does:
   * Returns TRUE when dword lane at input+40 equals compare value.
   */
  BOOL LegacyIsDwordAtInputPlus40EqualRuntimeLaneAlpha(
    const std::uint8_t* const inputValue,
    const std::int32_t /*unusedArgument*/,
    const std::uint32_t compareValue
  )
  {
    const auto* const lane40 = reinterpret_cast<const std::uint32_t*>(inputValue + 40);
    return (lane40[0] == compareValue) ? TRUE : FALSE;
  }

  std::uintptr_t& LegacyPointerInitLaneWord0State()
  {
    static std::uintptr_t value = 0U;
    return value;
  }

  std::uintptr_t& LegacyPointerInitLaneWord4State()
  {
    static std::uintptr_t value = 0U;
    return value;
  }

  std::uintptr_t& LegacyPointerInitLaneWord8Storage()
  {
    static std::uintptr_t value = 0U;
    return value;
  }

  /**
   * Address: 0x009CFD00 (FUN_009CFD00)
   *
   * What it does:
   * Stores lane word4 as address of lane word8 storage and clears lane word0.
   */
  void LegacyInitializePointerAndClearLaneRuntimeAlpha()
  {
    LegacyPointerInitLaneWord4State() =
      reinterpret_cast<std::uintptr_t>(&LegacyPointerInitLaneWord8Storage());
    LegacyPointerInitLaneWord0State() = 0U;
  }

  struct LegacyDoubleOctetRuntimeLane
  {
    double lane00 = 0.0; // +0x00
    double lane08 = 0.0; // +0x08
    double lane10 = 0.0; // +0x10
    double lane18 = 0.0; // +0x18
    double lane20 = 0.0; // +0x20
    double lane28 = 0.0; // +0x28
    double lane30 = 0.0; // +0x30
    double lane38 = 0.0; // +0x38
  };
  static_assert(sizeof(LegacyDoubleOctetRuntimeLane) == 0x40, "LegacyDoubleOctetRuntimeLane size must be 0x40");

  /**
   * Address: 0x009CFD20 (FUN_009CFD20)
   *
   * What it does:
   * Appends one 8-double record at the current global write cursor, increments
   * the global record-count lane, advances the write cursor by `0x40`, and
   * returns the advanced cursor address.
   */
  std::uintptr_t LegacyAppendEightDoublesToLinearBufferRuntimeAlpha(
    const double lane00,
    const double lane08,
    const double lane10,
    const double lane18,
    const double lane20,
    const double lane28,
    const double lane30,
    const double lane38
  )
  {
    auto* const writeCursor = reinterpret_cast<LegacyDoubleOctetRuntimeLane*>(LegacyPointerInitLaneWord4State());
    writeCursor->lane00 = lane00;
    LegacyPointerInitLaneWord0State() += 1U;
    writeCursor->lane08 = lane08;

    const auto advancedCursorAddress =
      reinterpret_cast<std::uintptr_t>(writeCursor) + sizeof(LegacyDoubleOctetRuntimeLane);
    LegacyPointerInitLaneWord4State() = advancedCursorAddress;

    writeCursor->lane10 = lane10;
    writeCursor->lane18 = lane18;
    writeCursor->lane20 = lane20;
    writeCursor->lane28 = lane28;
    writeCursor->lane30 = lane30;
    writeCursor->lane38 = lane38;
    return advancedCursorAddress;
  }

  /**
   * Address: 0x00ABFA9B (FUN_00ABFA9B, std::uncaught_exception)
   *
   * What it does:
   * Linker-emitted trampoline for the exported `std::uncaught_exception`
   * symbol; jumps directly to the already-recovered `__uncaught_exception`
   * CRT helper (0x00AA2A65) with no intervening logic.
   */
  bool ThunkStdUncaughtException()
  {
    return __uncaught_exception();
  }

} // namespace moho::runtime







