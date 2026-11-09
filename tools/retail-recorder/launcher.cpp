// recorder.exe <out.txt> <timeout-seconds> <game-log-or-"-"> <exe> [args...]
//
// Starts the game minimized, loads recorder.dll (next to this exe) into it
// once its window is idle (before the replay's sim starts), and waits until
// it exits, the timeout passes, or the game log shows the parity hook's
// "over=true" heartbeat; then ends it (the last unflushed lines are lost, and a
// cut-off last line reads as BAD in faf_math_dump --values). The DLL writes its lines to <out.txt>
// (RETAIL_RECORDER_OUT). Exit code: the game's, or 124 on a timeout.
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace
{
  std::wstring Quote(const wchar_t* arg)
  {
    std::wstring s = L"\"";
    s += arg;
    s += L"\"";
    return s;
  }

  bool LogSaysOver(const wchar_t* path)
  {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
      return false;
    }
    LARGE_INTEGER size{};
    GetFileSizeEx(f, &size);
    const LONGLONG tail = size.QuadPart > 65536 ? 65536 : size.QuadPart;
    LARGE_INTEGER pos{};
    pos.QuadPart = size.QuadPart - tail;
    SetFilePointerEx(f, pos, nullptr, FILE_BEGIN);
    std::string text(static_cast<std::size_t>(tail), '\0');
    DWORD read = 0;
    ReadFile(f, text.data(), static_cast<DWORD>(tail), &read, nullptr);
    CloseHandle(f);
    // The parity hook's heartbeat writes Lua's boolean: "over=true".
    return text.find("over=true") != std::string::npos || text.find("over=True") != std::string::npos;
  }
} // namespace

int wmain(int argc, wchar_t** argv)
{
  if (argc < 5) {
    std::fprintf(stderr, "usage: recorder.exe <out.txt> <timeout-seconds> <game-log|-> <exe> [args...]\n");
    return 2;
  }
  SetEnvironmentVariableW(L"RETAIL_RECORDER_OUT", argv[1]);
  const DWORD timeoutMs = static_cast<DWORD>(_wtoi(argv[2])) * 1000u;
  const wchar_t* const gameLog = std::wcscmp(argv[3], L"-") == 0 ? nullptr : argv[3];

  wchar_t dll[MAX_PATH];
  GetModuleFileNameW(nullptr, dll, MAX_PATH);
  wchar_t* slash = std::wcsrchr(dll, L'\\');
  std::wcscpy(slash != nullptr ? slash + 1 : dll, L"recorder.dll");
  char dllA[MAX_PATH];
  WideCharToMultiByte(CP_ACP, 0, dll, -1, dllA, MAX_PATH, nullptr, nullptr);

  std::wstring cmd = Quote(argv[4]);
  for (int i = 5; i < argc; ++i) {
    cmd += L" ";
    cmd += Quote(argv[i]);
  }
  std::wstring dir = argv[4];
  dir = dir.substr(0, dir.find_last_of(L"\\/"));

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_SHOWMINNOACTIVE;
  PROCESS_INFORMATION pi{};
  // Started normally and loaded into once it has finished starting up: a
  // remote LoadLibrary thread in a process created suspended runs the
  // process's own initialisation, which faulted in the thread pool
  // (ntdll!TpWaitForWait) and then recursed in the CRT's __decode_pointer. The
  // functions recorded run in the sim, well after the window is idle.
  if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, dir.c_str(), &si, &pi)) {
    std::fprintf(stderr, "recorder: CreateProcess failed (%lu)\n", GetLastError());
    return 3;
  }
  // A console program (our headless) has no window to wait for: this returns
  // at once, and the delay lets its own startup finish.
  WaitForInputIdle(pi.hProcess, 60000);
  wchar_t delay[16] = {};
  if (GetEnvironmentVariableW(L"RETAIL_RECORDER_INJECT_DELAY_MS", delay, 16) != 0) {
    Sleep(static_cast<DWORD>(_wtoi(delay)));
  }

  void* remote = VirtualAllocEx(pi.hProcess, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  WriteProcessMemory(pi.hProcess, remote, dllA, std::strlen(dllA) + 1, nullptr);
  auto* const loadLibrary =
    reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA"));
  HANDLE thread = CreateRemoteThread(pi.hProcess, nullptr, 0, loadLibrary, remote, 0, nullptr);
  DWORD loaded = 0;
  if (thread == nullptr || WaitForSingleObject(thread, 30000) != WAIT_OBJECT_0 || !GetExitCodeThread(thread, &loaded) ||
      loaded == 0) {
    std::fprintf(stderr, "recorder: recorder.dll did not load into the game\n");
    TerminateProcess(pi.hProcess, 3);
    return 3;
  }
  CloseHandle(thread);

  const ULONGLONG start = GetTickCount64();
  DWORD exitCode = 124;
  for (;;) {
    if (WaitForSingleObject(pi.hProcess, 2000) == WAIT_OBJECT_0) {
      GetExitCodeProcess(pi.hProcess, &exitCode);
      break;
    }
    if (gameLog != nullptr && LogSaysOver(gameLog)) {
      Sleep(12000); // let the recorder flush its last lines and rewrite its table (every 10 s)
      TerminateProcess(pi.hProcess, 0);
      exitCode = 0;
      break;
    }
    if (GetTickCount64() - start > timeoutMs) {
      TerminateProcess(pi.hProcess, 124);
      break;
    }
  }
  std::fprintf(stdout, "recorder: game ended with %lu after %llu s\n", exitCode, (GetTickCount64() - start) / 1000ull);
  return static_cast<int>(exitCode);
}
