// Engine addition (dedicated-server plan WPL.5): the platform services of
// moho/misc/WinPlatform.cpp for the Linux build, which leaves that file out (it is built on
// dbghelp, message boxes and the crash-report attachment list).
//
// Call stacks come from backtrace(3) and are symbolised with dladdr(3); a message box is a
// line on stderr; the error-report attachments are kept as on Windows but nothing sends them.

#if !defined(_WIN32)

#include "moho/app/WinApp.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include <cxxabi.h>
#include <dlfcn.h>
#include <execinfo.h>

#include "gpg/core/containers/String.h"

// Declared in WinApp.h; the client's TUs set them (none on Linux).
moho::OkBoxOwnerWindowHook moho::sOkBoxOwnerWindow = nullptr;
moho::AppExitMainLoopHook moho::sAppExitMainLoop = nullptr;
moho::AppPumpEventsHook moho::sAppPumpEvents = nullptr;
moho::AppPumpStepHook moho::sAppPumpStep = nullptr;

namespace
{
  std::mutex gReportFilesLock;
  std::wstring gReportOutputDir;
  std::vector<std::wstring> gReportFiles;
} // namespace

void moho::PLAT_Init() {}

void moho::PLAT_Exit() {}

void moho::PLAT_InitErrorReportOutputDir(const wchar_t* const outputDir)
{
  const std::lock_guard<std::mutex> lock(gReportFilesLock);
  gReportOutputDir = outputDir != nullptr ? outputDir : L"";
  if (!gReportOutputDir.empty() && gReportOutputDir.back() != L'\\' && gReportOutputDir.back() != L'/') {
    gReportOutputDir.push_back(L'\\');
  }
}

void moho::PLAT_RegisterFileForErrorReport(const wchar_t* const file)
{
  if (file == nullptr || file[0] == L'\0') {
    return;
  }
  const std::lock_guard<std::mutex> lock(gReportFilesLock);
  for (const std::wstring& known : gReportFiles) {
    if (known == file) {
      return;
    }
  }
  gReportFiles.emplace_back(file);
}

std::wstring moho::PLAT_GetErrorReportOutputDir()
{
  const std::lock_guard<std::mutex> lock(gReportFilesLock);
  return gReportOutputDir;
}

std::uint32_t moho::PLAT_GetCallStack(void* const contextRecord, const std::uint32_t maxFrames, std::uintptr_t* const outFrames)
{
  // Only the calling thread's own stack: a fault context's stack is the signal handler's.
  (void)contextRecord;
  if (outFrames == nullptr || maxFrames == 0) {
    return 0;
  }
  std::vector<void*> frames(maxFrames + 1u);
  const int count = ::backtrace(frames.data(), static_cast<int>(frames.size()));
  // Frame 0 is this function, as the Windows walk starts at its caller.
  std::uint32_t written = 0;
  for (int index = 1; index < count && written < maxFrames; ++index) {
    outFrames[written++] = reinterpret_cast<std::uintptr_t>(frames[static_cast<std::size_t>(index)]);
  }
  return written;
}

bool moho::PLAT_GetSymbolInfo(const std::uintptr_t address, SPlatSymbolInfo* const outInfo)
{
  if (outInfo == nullptr) {
    return false;
  }
  Dl_info info{};
  if (::dladdr(reinterpret_cast<void*>(address), &info) == 0 || info.dli_sname == nullptr) {
    return false;
  }
  outInfo->addr = address;
  int status = 0;
  char* const demangled = abi::__cxa_demangle(info.dli_sname, nullptr, nullptr, &status);
  outInfo->symbol.assign_owned(status == 0 && demangled != nullptr ? demangled : info.dli_sname);
  std::free(demangled);
  outInfo->symDis = address - reinterpret_cast<std::uintptr_t>(info.dli_saddr);
  outInfo->filename.assign_owned(info.dli_fname != nullptr ? info.dli_fname : "(Unknown)");
  outInfo->lineNum = 0;
  outInfo->lineDis = 0;
  return true;
}

msvc8::string moho::SPlatSymbolInfo::FormatResolvedLine() const
{
  return gpg::STR_Printf("%s + %zu bytes (%s(%u) + %u bytes)", symbol.c_str(), symDis, filename.c_str(), lineNum, lineDis);
}

msvc8::string moho::PLAT_FormatCallstack(std::int32_t firstFrame, const std::int32_t endFrame, const std::uintptr_t* const frames)
{
  msvc8::string formatted;
  formatted.assign_owned("");
  if (frames == nullptr || firstFrame >= endFrame) {
    return formatted;
  }
  if (firstFrame < 0) {
    firstFrame = 0;
  }
  std::string assembled;
  for (std::int32_t frameIndex = firstFrame; frameIndex < endFrame; ++frameIndex) {
    SPlatSymbolInfo symbolInfo{};
    if (PLAT_GetSymbolInfo(frames[frameIndex], &symbolInfo)) {
      assembled.append("\t");
      assembled.append(symbolInfo.FormatResolvedLine().c_str());
      assembled.append("\r\n");
    } else {
      const msvc8::string line =
        gpg::STR_Printf("\tUnknown symbol (address %p)\r\n", reinterpret_cast<const void*>(frames[frameIndex]));
      assembled.append(line.c_str());
    }
  }
  formatted.assign_owned(assembled);
  return formatted;
}

msvc8::string moho::PLAT_UnDecorateSymbolName(const char* const name, const bool stripLeadingUnderscore)
{
  (void)stripLeadingUnderscore;
  msvc8::string result;
  if (name == nullptr) {
    result.assign_owned("");
    return result;
  }
  int status = 0;
  char* const demangled = abi::__cxa_demangle(name, nullptr, nullptr, &status);
  result.assign_owned(status == 0 && demangled != nullptr ? demangled : name);
  std::free(demangled);
  return result;
}

msvc8::string moho::WIN_GetLastError()
{
  const DWORD errorCode = ::GetLastError();
  // The shim's error codes are Win32 numbers for the common cases and errno values otherwise.
  return gpg::STR_Printf("error %u (%s)", static_cast<unsigned>(errorCode), std::strerror(static_cast<int>(errorCode)));
}

void moho::WIN_OkBox(const gpg::StrArg caption, const gpg::StrArg text)
{
  std::fprintf(stderr, "[%s] %s\n", caption != nullptr ? caption : "", text != nullptr ? text : "");
  std::fflush(stderr);
}

#endif // !defined(_WIN32)
